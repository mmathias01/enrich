/*
 * Copyright (c) 2020-2021 Snowplow Analytics Ltd. All rights reserved.
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
package com.snowplowanalytics.snowplow.enrich.common.fs2

import java.nio.charset.StandardCharsets.UTF_8
import java.time.Instant
import java.util.Base64
import java.util.concurrent.TimeUnit

import org.joda.time.DateTime

import cats.data.{NonEmptyList, Validated, ValidatedNel}
import cats.{Monad, Parallel}
import cats.implicits._

import cats.effect.{Clock, Concurrent, ContextShift, Sync}

import fs2.{Pipe, Stream}

import _root_.io.sentry.SentryClient

import _root_.io.circe.Json
import _root_.io.circe.syntax._

import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger

import com.snowplowanalytics.iglu.client.Client
import com.snowplowanalytics.iglu.client.resolver.registries.RegistryLookup

import com.snowplowanalytics.snowplow.badrows.{Processor, BadRow, Failure, Payload => BadRowPayload}

import com.snowplowanalytics.snowplow.enrich.common.EtlPipeline
import com.snowplowanalytics.snowplow.enrich.common.outputs.EnrichedEvent
import com.snowplowanalytics.snowplow.enrich.common.adapters.AdapterRegistry
import com.snowplowanalytics.snowplow.enrich.common.loaders.{CollectorPayload, ThriftLoader}
import com.snowplowanalytics.snowplow.enrich.common.enrichments.EnrichmentRegistry
import com.snowplowanalytics.snowplow.enrich.common.utils.ConversionUtils

object Enrich {

  /**
   * Parallelism of an enrich stream.
   * Unlike for thread pools it doesn't make much sense to use `CPUs x 2` formulae
   * as we're not sizing threads, but fibers and memory is the only cost of them
   */
  val ConcurrencyLevel = 64

  /** Default adapter registry, can be constructed dynamically in future */
  val adapterRegistry = new AdapterRegistry()

  private implicit def unsafeLogger[F[_]: Sync]: Logger[F] =
    Slf4jLogger.getLogger[F]

  /**
   * Run a primary enrichment stream, reading from [[Environment]] source, enriching
   * via [[enrichWith]] and sinking into the Good, Bad, and Pii sinks.
   * Can be stopped via _stop signal_ from [[Environment]]
   *
   * The stream won't download any enrichment DBs, it is responsibility of [[Assets]]
   * [[Assets.State.make]] downloads assets for the first time unconditionally during
   * [[Environment]] initialisation, then if `assetsUpdatePeriod` has been specified -
   * they'll be refreshed periodically by [[Assets.updateStream]]
   *
   * @param ordered indicates whether the events should be processed ordered or not
   */
  def run[F[_]: Concurrent: ContextShift: Clock: Parallel, A](env: Environment[F, A], ordered: Boolean): Stream[F, Unit] = {
    val registry: F[EnrichmentRegistry[F]] = env.enrichments.get.map(_.registry)
    val enrich: Enrich[F] = {
      implicit val rl: RegistryLookup[F] = env.registryLookup
      enrichWith[F](registry, env.igluClient, env.sentry, env.metrics.enrichLatency, env.processor)
    }

    val enrichPipe: Pipe[F, (A, Array[Byte]), (A, Result)] =
      if(ordered)
        _.parEvalMapUnordered(ConcurrencyLevel){ case (orig, bytes) => enrich(bytes).map((orig, _)) }
      else
        _.parEvalMap(ConcurrencyLevel){ case (orig, bytes) => enrich(bytes).map((orig, _)) }

    env.source
      .pauseWhen(env.pauseEnrich)
      .evalTap(_ => env.metrics.rawCount)
      .map(a => (a, env.getPayload(a)))
      .through(enrichPipe)
      .through(sinkAll(sinkResult(env)))
      .through(env.checkpointer)
  }

  /**
   * Enrich a single `CollectorPayload` to get list of bad rows and/or enriched events
   * `enrichLatency` gauge gets updated for each event
   */
  def enrichWith[F[_]: Clock: ContextShift: RegistryLookup: Sync](
    enrichRegistry: F[EnrichmentRegistry[F]],
    igluClient: Client[F, Json],
    sentry: Option[SentryClient],
    enrichLatency: Option[Long] => F[Unit],
    processor: Processor
  )(
    row: Array[Byte]
  ): F[Result] = {
    val payload = ThriftLoader.toCollectorPayload(row, processor)
    val collectorTstamp = payload.toOption.flatMap(_.flatMap(_.context.timestamp).map(_.getMillis))

    val result =
      for {
        _ <- Logger[F].debug(payloadToString(payload))
        etlTstamp <- Clock[F].realTime(TimeUnit.MILLISECONDS).map(millis => new DateTime(millis))
        registry <- enrichRegistry
        enriched <- EtlPipeline.processEvents[F](adapterRegistry, registry, igluClient, processor, etlTstamp, payload)
        _ <- enrichLatency(collectorTstamp)
      } yield enriched

    result.handleErrorWith(sendToSentry[F](row, sentry, processor))
  }

  /** Stringify `ThriftLoader` result for debugging purposes */
  def payloadToString(payload: ValidatedNel[BadRow.CPFormatViolation, Option[CollectorPayload]]): String =
    payload.fold(_.asJson.noSpaces, _.map(_.toBadRowPayload.asJson.noSpaces).getOrElse("None"))

  /** Log an error, turn the problematic `CollectorPayload` into `BadRow` and notify Sentry if configured */
  def sendToSentry[F[_]: Sync: Clock]
      (original: Array[Byte], sentry: Option[SentryClient], processor: Processor)
      (error: Throwable): F[Result] =
    for {
      _ <- Logger[F].error("Runtime exception during payload enrichment. CollectorPayload converted to generic_error and ack'ed")
      now <- Clock[F].realTime(TimeUnit.MILLISECONDS).map(Instant.ofEpochMilli)
      badRow = genericBadRow(original, now, error, processor)
      _ <- sentry match {
             case Some(client) =>
               Sync[F].delay(client.sendException(error))
             case None =>
               Sync[F].unit
           }
    } yield List(badRow.invalid)

  /** Build a `generic_error` bad row for unhandled runtime errors */
  def genericBadRow(
    row: Array[Byte],
    time: Instant,
    error: Throwable,
    processor: Processor
  ): BadRow.GenericError = {
    val base64 = new String(Base64.getEncoder.encode(row))
    val rawPayload = BadRowPayload.RawPayload(base64)
    val failure = Failure.GenericFailure(time, NonEmptyList.one(error.toString))
    BadRow.GenericError(processor, failure, rawPayload)
  }

  def sinkBad[F[_]: Monad, A](env: Environment[F, A], bad: BadRow): F[Unit] =
    env.metrics.badCount >> env.bad(bad.compact.getBytes(UTF_8))

  def sinkGood[F[_]: Concurrent: Parallel, A](env: Environment[F, A], enriched: EnrichedEvent): F[Unit] =
    serializeEnriched(enriched, env.processor) match {
      case Left(br) => sinkBad(env, br)
      case Right(bytes) =>
        List(env.metrics.goodCount, env.good(AttributedData(bytes, env.goodAttributes(enriched))), sinkPii(env, enriched)).parSequence_
    }

  def sinkPii[F[_]: Monad, A](env: Environment[F, A], enriched: EnrichedEvent): F[Unit] =
    (for {
      piiSink <- env.pii
      pii <- ConversionUtils.getPiiEvent(env.processor, enriched)
    } yield serializeEnriched(pii, env.processor) match {
      case Left(br) => sinkBad(env, br)
      case Right(bytes) => piiSink(AttributedData(bytes, env.piiAttributes(pii)))
    }).getOrElse(Monad[F].unit)

  def serializeEnriched(enriched: EnrichedEvent, processor: Processor): Either[BadRow, Array[Byte]] = {
    val asStr = ConversionUtils.tabSeparatedEnrichedEvent(enriched)
    val asBytes = asStr.getBytes(UTF_8)
    val size = asBytes.length
    if (size > MaxRecordSize) {
      val msg = s"event passed enrichment but then exceeded the maximum allowed size $MaxRecordSize"
      val br = BadRow
        .SizeViolation(
          processor,
          Failure.SizeViolation(Instant.now(), MaxRecordSize, size, msg),
          BadRowPayload.RawPayload(asStr.take(MaxErrorMessageSize))
        )
      Left(br)
    } else Right(asBytes)
  }

  def sinkAll[F[_]: Concurrent: Parallel, A, B](f: B => F[Unit]): Pipe[F, (A, List[B]), A] =
    _.parEvalMap(SinkConcurrency){case (a, bs) => bs.parTraverse_(f).map(_ => a)}

  def sinkResult[F[_]: Concurrent: Parallel, A](env: Environment[F, A])(result: Validated[BadRow, EnrichedEvent]): F[Unit] =
    result.fold(sinkBad(env, _), sinkGood(env, _))

  /**
   * The maximum size of a serialized payload that can be written to pubsub.
   *
   *  Equal to 6.9 MB. The message will be base64 encoded by the underlying library, which brings the
   *  encoded message size to near 10 MB, which is the maximum allowed for PubSub.
   */
  private val MaxRecordSize = 6900000

  /** The maximum substring of the message that we write into a SizeViolation bad row */
  private val MaxErrorMessageSize = MaxRecordSize / 10

  /**
   * Controls the maximum number of events we can be waiting to get sunk
   *
   *  For the Pubsub sink this should at least exceed the number events we can sink within
   *  `Sink.DefaultDelayThreshold`.
   *
   *  For the FileSystem source this is the primary way that we control the memory footprint of the
   *  app.
   */
  private val SinkConcurrency = 10000
}
