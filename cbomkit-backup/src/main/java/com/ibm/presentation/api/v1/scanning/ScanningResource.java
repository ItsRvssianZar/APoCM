/*
 * CBOMkit
 * Copyright (C) 2025 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.presentation.api.v1.scanning;

import static com.ibm.output.IAggregator.LOGGER;

import app.bootstrap.core.cqrs.ICommandBus;
import app.bootstrap.core.ddd.IDomainEventBus;
import com.ibm.domain.scanning.ScanId;
import com.ibm.domain.scanning.authentication.ICredentials;
import com.ibm.infrastructure.progress.EmptyProgressDispatcher;
import com.ibm.infrastructure.scanning.IScanConfiguration;
import com.ibm.infrastructure.scanning.repositories.ScanRepository;
import com.ibm.usecases.scanning.commands.CloneGitRepositoryCommand;
import com.ibm.usecases.scanning.commands.IdentifyPackageFolderCommand;
import com.ibm.usecases.scanning.commands.IndexModulesCommand;
import com.ibm.usecases.scanning.commands.RequestScanCommand;
import com.ibm.usecases.scanning.commands.ResolvePurlCommand;
import com.ibm.usecases.scanning.commands.ScanCommand;
import com.ibm.usecases.scanning.processmanager.ScanProcessManager;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import java.util.List;

@Path("/api/v1/scan")
@ApplicationScoped
public final class ScanningResource {

    @Nonnull private final ICommandBus commandBus;
    @Nonnull private final IDomainEventBus domainEventBus;
    @Nonnull private final IScanConfiguration configuration;

    public ScanningResource(
            @Nonnull ICommandBus commandBus,
            @Nonnull IDomainEventBus domainEventBus,
            @Nonnull IScanConfiguration configuration) {
        this.commandBus = commandBus;
        this.domainEventBus = domainEventBus;
        this.configuration = configuration;
    }

    @POST
    public Response scan(@Nullable ScanRequest scanRequest) {
        if (scanRequest == null) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        try {
            final ScanRepository scanRepository = new ScanRepository(this.domainEventBus);

            final ScanId scanId = new ScanId();
            final ScanProcessManager scanProcessManager =
                    new ScanProcessManager(
                            scanId,
                            this.commandBus,
                            scanRepository,
                            new EmptyProgressDispatcher(),
                            this.configuration);

            this.commandBus.register(
                    scanProcessManager,
                    List.of(
                            ResolvePurlCommand.class,
                            CloneGitRepositoryCommand.class,
                            IdentifyPackageFolderCommand.class,
                            IndexModulesCommand.class,
                            ScanCommand.class));

            final ICredentials authCredentials = Credentials.extractFrom(scanRequest);

            commandBus.send(
                    new RequestScanCommand(
                            scanId,
                            scanRequest.scanUrl(),
                            scanRequest.branch(),
                            scanRequest.subfolder(),
                            authCredentials));

            return Response.status(Response.Status.ACCEPTED).build();
        } catch (Exception e) {
            LOGGER.error("Error processing request", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }
}
