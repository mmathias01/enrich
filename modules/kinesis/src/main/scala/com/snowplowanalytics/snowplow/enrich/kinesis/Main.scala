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
package com.snowplowanalytics.snowplow.enrich.kinesis

import cats.effect.{ExitCode, IO, IOApp, Resource, SyncIO}

import java.util.concurrent.{Executors, TimeUnit}

import scala.collection.mutable.ArrayBuffer
import scala.concurrent.ExecutionContext

import fs2.aws.kinesis.CommittableRecord

import com.snowplowanalytics.snowplow.enrich.common.fs2.Run

import com.snowplowanalytics.snowplow.enrich.kinesis.generated.BuildInfo

object Main extends IOApp.WithContext {

  /**
   * An execution context matching the cats effect IOApp default. We create it explicitly so we can
   * also use it for our Blaze client.
   */
  override protected val executionContextResource: Resource[SyncIO, ExecutionContext] = {
    val poolSize = math.max(2, Runtime.getRuntime().availableProcessors())
    Resource
      .make(SyncIO(Executors.newFixedThreadPool(poolSize)))(pool =>
        SyncIO {
          pool.shutdown()
          pool.awaitTermination(10, TimeUnit.SECONDS)
          ()
        }
      )
      .map(ExecutionContext.fromExecutorService)
  }

  def run(args: List[String]): IO[ExitCode] =
    Run.run[IO, CommittableRecord](
      args,
      BuildInfo.name,
      BuildInfo.version,
      BuildInfo.description,
      executionContext,
      Source.init,
      Sink.initAttributed,
      Sink.initAttributed,
      Sink.init,
      getPayload,
      false
    )

  private def getPayload(record: CommittableRecord): Array[Byte] = {
    val data = record.record.data
    val buffer = ArrayBuffer[Byte]()
    while (data.hasRemaining())
      buffer.append(data.get)
    buffer.toArray
  }
}
