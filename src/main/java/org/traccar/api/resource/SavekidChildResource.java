/*
 * Copyright 2025 SaveKID
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.api.resource;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.traccar.api.BaseObjectResource;
import org.traccar.model.Device;
import org.traccar.model.SavekidChild;
import org.traccar.model.User;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Order;
import org.traccar.storage.query.Request;

import java.util.Date;
import java.util.LinkedList;
import java.util.stream.Stream;

@Path("savekid/children")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class SavekidChildResource extends BaseObjectResource<SavekidChild> {

    public SavekidChildResource() {
        super(SavekidChild.class);
    }

    @GET
    public Stream<SavekidChild> get(
            @QueryParam("all") boolean all,
            @QueryParam("userId") long userId,
            @QueryParam("deviceId") long deviceId) throws StorageException {

        var conditions = new LinkedList<Condition>();

        if (all) {
            if (permissionsService.notAdmin(getUserId())) {
                conditions.add(new Condition.Permission(User.class, getUserId(), SavekidChild.class));
            }
        } else {
            if (userId == 0) {
                userId = getUserId();
            } else {
                permissionsService.checkUser(getUserId(), userId);
            }
            conditions.add(new Condition.Permission(User.class, userId, SavekidChild.class));
        }

        if (deviceId > 0) {
            permissionsService.checkPermission(Device.class, getUserId(), deviceId);
            conditions.add(new Condition.Equals("deviceId", deviceId));
        }

        return storage.getObjectsStream(SavekidChild.class, new Request(
                new Columns.All(), Condition.merge(conditions), new Order("name")));
    }

    @Override
    public Response add(SavekidChild entity) throws Exception {
        Date now = new Date();
        entity.setCreatedAt(now);
        entity.setUpdatedAt(now);
        if (entity.getDeviceId() != null) {
            permissionsService.checkPermission(Device.class, getUserId(), entity.getDeviceId());
        }
        return super.add(entity);
    }

    @Path("{id}")
    @PUT
    @Override
    public Response update(SavekidChild entity) throws Exception {
        permissionsService.checkPermission(SavekidChild.class, getUserId(), entity.getId());
        SavekidChild existing = storage.getObject(SavekidChild.class, new Request(
                new Columns.All(), new Condition.Equals("id", entity.getId())));
        if (existing != null && entity.getCreatedAt() == null) {
            entity.setCreatedAt(existing.getCreatedAt());
        }
        if (entity.getDeviceId() != null) {
            permissionsService.checkPermission(Device.class, getUserId(), entity.getDeviceId());
        }
        entity.setUpdatedAt(new Date());
        return super.update(entity);
    }

    @Path("by-device/{deviceId}")
    @GET
    public Response getByDevice(@PathParam("deviceId") long deviceId) throws StorageException {
        permissionsService.checkPermission(Device.class, getUserId(), deviceId);
        SavekidChild child = storage.getObject(SavekidChild.class, new Request(
                new Columns.All(), new Condition.Equals("deviceId", deviceId)));
        if (child != null) {
            return Response.ok(child).build();
        }
        return Response.status(Response.Status.NOT_FOUND).build();
    }
}
