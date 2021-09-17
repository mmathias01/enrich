/*
 * Copyright (c) 2021-2021 Snowplow Analytics Ltd. All rights reserved.
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

import java.nio.ByteBuffer
import java.util.UUID

import cats.implicits._

import cats.effect.{Async, Blocker, Concurrent, ContextShift, Resource, Sync, Timer}

import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger

import fs2.aws.internal.{KinesisProducerClient, KinesisProducerClientImpl}

import retry.syntax.all._
import retry.RetryPolicies._

import com.google.common.util.concurrent.{FutureCallback, Futures, ListenableFuture}

import com.amazonaws.services.kinesis.producer.{KinesisProducerConfiguration, UserRecordResult}

import com.snowplowanalytics.snowplow.enrich.common.fs2.{AttributedByteSink, AttributedData, ByteSink}
import com.snowplowanalytics.snowplow.enrich.common.fs2.config.io.{Monitoring, Output}

object Sink {

  private implicit def unsafeLogger[F[_]: Sync]: Logger[F] =
    Slf4jLogger.getLogger[F]

  def init[F[_]: Concurrent: ContextShift: Timer](
    blocker: Blocker,
    output: Output,
    monitoring: Option[Monitoring]
  ): Resource[F, ByteSink[F]] =
    output match {
      case o: Output.Kinesis =>
        kinesis[F](blocker, o, monitoring).map(sink => bytes => sink(AttributedData(bytes, Map.empty)))
      case o =>
        throw new IllegalArgumentException(s"Output $o is not Kinesis")
    }

  def initAttributed[F[_]: Concurrent: ContextShift: Timer](
    blocker: Blocker,
    output: Output,
    monitoring: Option[Monitoring]
  ): Resource[F, AttributedByteSink[F]] =
    output match {
      case o: Output.Kinesis =>
        kinesis[F](blocker, o, monitoring)
      case o =>
        throw new IllegalArgumentException(s"Output $o is not Kinesis")
    }

  private def kinesis[F[_]: Async: Timer](
    blocker: Blocker,
    config: Output.Kinesis,
    monitoring: Option[Monitoring]
  ): Resource[F, AttributedData[Array[Byte]] => F[Unit]] =
    mkProducer(config, monitoring).map(writeToKinesis(blocker, config))

  private def mkProducer[F[_]: Sync](
    config: Output.Kinesis,
    monitoring: Option[Monitoring]
  ): Resource[F, KinesisProducerClient[F]] =
    Resource.eval(
      Sync[F].delay(
        new KinesisProducerClientImpl[F](Some(mkProducerConfig(config, monitoring)))
      )
    )

  private def mkProducerConfig[F[_]](config: Output.Kinesis, monitoring: Option[Monitoring]): KinesisProducerConfiguration = {
    val disableCloudwatch = monitoring.fold(false)(m => m.metrics.fold(false)(r => r.cloudwatch.contains(true)))
    val metricsLevel = if (disableCloudwatch) "none" else "detailed"

    new KinesisProducerConfiguration()
      .setThreadingModel(KinesisProducerConfiguration.ThreadingModel.POOLED)
      .setRegion(config.region)
      .setMetricsLevel(metricsLevel)
      .setCollectionMaxCount(config.maxBatchSize)
      .setCollectionMaxSize(config.maxBatchBytes)
      .setRecordMaxBufferedTime(config.delayThreshold.toMillis)
  }

  private def writeToKinesis[F[_]: Async: Timer](
    blocker: Blocker,
    config: Output.Kinesis
  )(
    producer: KinesisProducerClient[F]
  )(
    data: AttributedData[Array[Byte]]
  ): F[Unit] = {
    val retryPolicy = capDelay[F](config.backoffPolicy.maxBackoff, exponentialBackoff[F](config.backoffPolicy.minBackoff))
    val partitionKey = data.attributes.toList match { // there can be only one attribute : the partition key
      case head :: Nil => head._2
      case _ => UUID.randomUUID().toString
    }
    val res = for {
      byteBuffer <- Async[F].delay(ByteBuffer.wrap(data.data))
      cb <- producer.putData(config.streamName, partitionKey, byteBuffer)
      cbRes <- registerCallback(blocker, cb)
    } yield cbRes
    res
      .retryingOnFailuresAndAllErrors(
        wasSuccessful = _.isSuccessful,
        policy = retryPolicy,
        onFailure = (result, retryDetails) =>
          Logger[F].warn(s"Writing to shard ${result.getShardId()} failed after ${retryDetails.retriesSoFar} retry"),
        onError = (exception, retryDetails) =>
          Logger[F]
            .error(s"Writing to Kinesis errored after ${retryDetails.retriesSoFar} retry. Error: ${exception.toString}") >>
            Async[F].raiseError(exception)
      )
      .void
  }

  private def registerCallback[F[_]: Async](blocker: Blocker, f: ListenableFuture[UserRecordResult]): F[UserRecordResult] =
    Async[F].async[UserRecordResult] { cb =>
      Futures.addCallback(
        f,
        new FutureCallback[UserRecordResult] {
          override def onFailure(t: Throwable): Unit = cb(Left(t))
          override def onSuccess(result: UserRecordResult): Unit = cb(Right(result))
        },
        (command: Runnable) => blocker.blockingContext.execute(command)
      )
    }
}
