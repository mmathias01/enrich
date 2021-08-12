/*
 * Copyright (c) 2012-2021 Snowplow Analytics Ltd. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package com.snowplowanalytics.snowplow.enrich.common

package enrichments.registry

import io.circe.literal._

import org.specs2.Specification

import com.snowplowanalytics.iglu.core.{SchemaKey, SchemaVer, SelfDescribingData}

import com.snowplowanalytics.snowplow.badrows.FailureDetails

import outputs.EnrichedEvent

class JavascriptScriptEnrichmentSpec extends Specification {
  def is = s2"""
  Javascript enrichment should fail if the function isn't valid                      $e1
  Javascript enrichment should fail if the function doesn't return an array          $e2
  Javascript enrichment should fail if the function doesn't return an array of SDJs  $e3
  Javascript enrichment should be able to access the fields of the enriched event    $e4
  Javascript enrichment should be able to update the fields of the enriched event    $e5
  Javascript enrichment should be able to throw an exception                         $e6
  Javascript enrichment should be able to return no new context                      $e7
  Javascript enrichment should be able to return 2 new contexts                      $e8
  Javascript enrichment should be able to proceed without return statement           $e9
  Javascript enrichment should be able to proceed with return null                   $e10
  Javascript enrichment should be able to update the fields without return statement $e11
  Javascript enrichment should be able to run regexes                                $e12
  """

  val schemaKey =
    SchemaKey("com.snowplowanalytics.snowplow", "javascript_script_config", "jsonschema", SchemaVer.Full(1, 0, 0))

  def e1 =
    JavascriptScriptEnrichment(schemaKey, "[").process(buildEnriched()) must beLeft(
      failureContains(_: FailureDetails.EnrichmentFailure, "Error compiling")
    )

  def e2 = {
    val function = s"""
      function process(event) {
        return { foo: "bar" }
      }"""
    JavascriptScriptEnrichment(schemaKey, function).process(buildEnriched()) must beLeft(
      failureContains(_: FailureDetails.EnrichmentFailure, "not read as an array")
    )
  }

  def e3 = {
    val function = s"""
      function process(event) {
        return [ { foo: "bar" } ]
      }"""
    JavascriptScriptEnrichment(schemaKey, function).process(buildEnriched()) must beLeft(
      failureContains(_: FailureDetails.EnrichmentFailure, "not self-desribing")
    )
  }

  def e4 = {
    val appId = "greatApp"
    val function = s"""
      function process(event) {
        return [ { schema: "iglu:com.acme/foo/jsonschema/1-0-0",
          data:   { appId: event.getApp_id() }
        } ];
      }"""
    JavascriptScriptEnrichment(schemaKey, function).process(buildEnriched(appId)) must beRight.like {
      case List(sdj) if sdj.data.noSpaces.contains(appId) => true
      case _ => false
    }
  }

  def e5 = {
    val appId = "greatApp"
    val enriched = buildEnriched(appId)
    val newAppId = "evenBetterApp"
    val function = s"""
      function process(event) {
        event.setApp_id("$newAppId")
        return [ { schema: "iglu:com.acme/foo/jsonschema/1-0-0",
          data:   { foo: "bar" }
        } ];
      }"""
    JavascriptScriptEnrichment(schemaKey, function).process(enriched)
    enriched.app_id must beEqualTo(newAppId)
  }

  def e6 = {
    val function = s"""
      function process(event) {
        throw "Error"
      }"""
    JavascriptScriptEnrichment(schemaKey, function).process(buildEnriched()) must beLeft(
      failureContains(_: FailureDetails.EnrichmentFailure, "Error during execution")
    )
  }

  def e7 = {
    val function = s"""
      function process(event) {
        return [ ];
      }"""
    JavascriptScriptEnrichment(schemaKey, function).process(buildEnriched()) must beRight
  }

  def e8 = {
    val function = s"""
      function process(event) {
        return [ { schema: "iglu:com.acme/foo/jsonschema/1-0-0",
          data:   { hello: "world" }
        }, { schema: "iglu:com.acme/bar/jsonschema/1-0-0",
          data:   { hello: "world" }
        } ];
      }"""

    val context1 =
      SelfDescribingData(
        SchemaKey("com.acme", "foo", "jsonschema", SchemaVer.Full(1, 0, 0)),
        json"""{"hello":"world"}"""
      )
    val context2 =
      SelfDescribingData(
        SchemaKey("com.acme", "bar", "jsonschema", SchemaVer.Full(1, 0, 0)),
        json"""{"hello":"world"}"""
      )
    JavascriptScriptEnrichment(schemaKey, function).process(buildEnriched()) must beRight.like {
      case List(c1, c2) if c1 == context1 && c2 == context2 => true
      case _ => false
    }
  }

  def e9 = {
    val function = s"""
      function process(event) {
        var a = 42     // no-op
      }"""

    JavascriptScriptEnrichment(schemaKey, function).process(buildEnriched()) must beRight(Nil)
  }

  def e10 = {
    val function = s"""
      function process(event) {
        return null
      }"""

    JavascriptScriptEnrichment(schemaKey, function).process(buildEnriched()) must beRight(Nil)
  }

  def e11 = {
    val appId = "greatApp"
    val enriched = buildEnriched(appId)
    val newAppId = "evenBetterApp"
    val function = s"""
      function process(event) {
        event.setApp_id("$newAppId")
      }"""
    JavascriptScriptEnrichment(schemaKey, function).process(enriched)
    enriched.app_id must beEqualTo(newAppId)
  }

  def e12 = {
    val enriched = buildEnriched()

    val origin = "https://example.slice.is/landing?jwt=a0.1b.33&foo=bar"
    val filtered = "https://example.slice.is/landing?jwt=****&foo=bar"
    val noToken = "https://example.slice.is/landing?foo=bar"
    enriched.page_url = origin
    enriched.page_urlquery = noToken

    val function = s"""
    function process(event) {
      var page_url = '';
      var page_urlquery = '';
      var page_referrer = '';
      var refr_urlquery = '';

      var page_url_jwt = '';
      var page_urlquery_jwt = '';
      var page_referrer_jwt = '';
      var refr_urlquery_jwt = '';

      var regex = /.*jwt=([A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*)&+/;

      try {
        page_url = event.getPage_url();
        page_urlquery = event.getPage_urlquery();
        page_referrer = event.getPage_referrer();
        refr_urlquery = event.getRefr_urlquery();
      } catch(err) {};


      try {
        page_url_jwt = page_url.match(regex) && page_url.match(regex)[1];
      } catch(err) {};

      try {
        page_urlquery_jwt = page_urlquery.match(regex) && page_urlquery.match(regex)[1];
      } catch(err) {};

      try {
        page_referrer_jwt = page_referrer.match(regex) && page_referrer.match(regex)[1];
      } catch(err) {};

      try {
        refr_urlquery_jwt = refr_urlquery.match(regex) && refr_urlquery.match(regex)[1];
      } catch(err) {};

      if (page_url){
        var updated_page_url = page_url.replace(page_url_jwt, '****');
        event.setPage_url(new String(updated_page_url));
      }

      if (page_urlquery){
        var updated_page_urlquery = page_urlquery.replace(page_urlquery_jwt, '****');
        event.setPage_urlquery(new String(updated_page_urlquery));
      }

      if (page_referrer){
        var updated_page_referrer = page_referrer.replace(page_referrer_jwt, '****');
        event.setPage_referrer(new String(updated_page_referrer));
      }

      if (refr_urlquery){
        var updated_refr_urlquery = refr_urlquery.replace(refr_urlquery_jwt, '****');
        event.setRefr_urlquery(new String(updated_refr_urlquery));
      }
    }"""

    JavascriptScriptEnrichment(schemaKey, function).process(enriched)

    val one = enriched.page_url must beEqualTo(filtered)
    val two = enriched.page_urlquery must beEqualTo(noToken)
    val three = enriched.page_referrer must beEqualTo(null)
    val four = enriched.refr_urlquery must beEqualTo(null)
    one and two and three and four
  }

  def buildEnriched(appId: String = "my super app"): EnrichedEvent = {
    val e = new EnrichedEvent()
    e.platform = "server"
    e.app_id = appId
    e
  }

  def failureContains(failure: FailureDetails.EnrichmentFailure, pattern: String): Boolean =
    failure match {
      case FailureDetails.EnrichmentFailure(_, FailureDetails.EnrichmentFailureMessage.Simple(msg)) if msg.contains(pattern) => true
      case _ => false
    }
}
