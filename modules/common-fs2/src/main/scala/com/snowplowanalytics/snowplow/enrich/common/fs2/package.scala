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
package com.snowplowanalytics.snowplow.enrich.common

import cats.data.{EitherT, Validated, ValidatedNel}

import _root_.fs2.Stream

import com.snowplowanalytics.snowplow.badrows.BadRow

import com.snowplowanalytics.snowplow.enrich.common.outputs.EnrichedEvent

package object fs2 {

  type Parsed[F[_], A] = EitherT[F, String, A]

  type ValidationResult[A] = ValidatedNel[String, A]

  /** Raw Thrift payloads coming from a collector */
  type RawSource[F[_]] = Stream[F, Array[Byte]]

  type ByteSink[F[_]] = Array[Byte] => F[Unit]
  type AttributedByteSink[F[_]] = AttributedData[Array[Byte]] => F[Unit]

  /** Enrichment result, containing list of (valid and invalid) results */
  type Result = List[Validated[BadRow, EnrichedEvent]]

  /** Function to transform an origin raw payload into good and/or bad rows */
  type Enrich[F[_]] = Array[Byte] => F[Result]
}
