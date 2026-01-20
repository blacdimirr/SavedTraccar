/*
 * Copyright 2025 Anton Tananaev (anton@traccar.org)
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
package org.traccar.protocol;

import io.netty.channel.Channel;
import org.traccar.BaseProtocolDecoder;
import org.traccar.Protocol;
import org.traccar.helper.DateBuilder;
import org.traccar.helper.Parser;
import org.traccar.helper.PatternBuilder;
import org.traccar.helper.UnitsConverter;
import org.traccar.model.Position;
import org.traccar.session.DeviceSession;

import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

public class Fa66sProtocolDecoder extends BaseProtocolDecoder {

    private static final Pattern PATTERN = new PatternBuilder()
            .text("$")
            .expression("FA66S,")
            .expression("([^,]+),")                  // device identifier (IMEI/ID)
            .number("(dddd)(dd)(dd),")               // date (yyyyMMdd)
            .number("(dd)(dd)(dd),")                 // time (HHmmss)
            .expression("([AV]),")                   // validity
            .number("(-?d+.?d*),")                   // latitude
            .number("(-?d+.?d*),")                   // longitude
            .number("(d+.?d*),")                     // speed (km/h)
            .number("(d+.?d*),")                     // course
            .number("(d+.?d*),")                     // battery level
            .number("(d+),")                         // heart rate
            .number("(d+.?d*),")                     // body temperature
            .number("(d+),")                         // steps
            .number("(d+),")                         // sleep status
            .number("(d)")                           // SOS flag
            .any()
            .compile();

    private static final long MAPPING_TIMEOUT = 24 * 60 * 60 * 1000L;

    private static final Pattern WIFI_PATTERN = Pattern.compile("(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}.*$");

    private static final Map<String, ImeiEntry> HEADER_TO_IMEI = new ConcurrentHashMap<>();

    public Fa66sProtocolDecoder(Protocol protocol) {
        super(protocol);
    }

    private Date decodeTime(Parser parser) {
        DateBuilder dateBuilder = new DateBuilder()
                .setYear(parser.nextInt(0))
                .setMonth(parser.nextInt(0))
                .setDay(parser.nextInt(0))
                .setHour(parser.nextInt(0))
                .setMinute(parser.nextInt(0))
                .setSecond(parser.nextInt(0));
        return dateBuilder.getDate();
    }

    @Override
    protected Object decode(Channel channel, SocketAddress remoteAddress, Object msg) throws Exception {

        String sentence = (String) msg;
        if (sentence.contains("[")) {
            List<String> frames = extractFrames(sentence);
            return decodeFrames(channel, remoteAddress, frames);
        }

        Parser parser = new Parser(PATTERN, sentence);
        if (!parser.matches()) {
            return null; // Ignore messages that do not match expected FA66S format
        }

        DeviceSession deviceSession = getDeviceSession(channel, remoteAddress, parser.next());
        if (deviceSession == null) {
            return null;
        }

        Position position = new Position(getProtocolName());
        position.setDeviceId(deviceSession.getDeviceId());

        position.setTime(decodeTime(parser));
        position.setValid(parser.next().equals("A"));
        position.setLatitude(parser.nextDouble(0));
        position.setLongitude(parser.nextDouble(0));
        position.setSpeed(UnitsConverter.knotsFromKph(parser.nextDouble(0)));
        position.setCourse(parser.nextDouble(0));

        position.set(Position.KEY_BATTERY_LEVEL, parser.nextDouble(0));

        int heartRate = parser.nextInt(0);
        position.set("heartRate", heartRate);

        double bodyTemp = parser.nextDouble(0);
        position.set("bodyTemp", bodyTemp);

        int steps = parser.nextInt(0);
        position.set("steps", steps);

        int sleepStatus = parser.nextInt(0);
        position.set("sleepStatus", sleepStatus);

        int sosFlag = parser.nextInt(0);
        if (sosFlag > 0) {
            position.set(Position.KEY_ALARM, Position.ALARM_SOS);
        }

        return position;
    }

    private Object decodeFrames(Channel channel, SocketAddress remoteAddress, List<String> frames) {
        List<Position> positions = new ArrayList<>();

        for (String frame : frames) {
            int commaIndex = frame.indexOf(',');
            if (commaIndex < 0) {
                continue;
            }

            String header = frame.substring(0, commaIndex);
            String[] headerParts = header.split("\\*");
            if (headerParts.length < 4) {
                continue;
            }

            String headerId = headerParts[1];
            String type = headerParts[3];
            String[] payload = frame.substring(commaIndex + 1).split(",", -1);

            if ("RYIMEI".equals(type)) {
                String imei = getValue(payload, 0);
                if (imei != null && !imei.isEmpty()) {
                    updateImeiMapping(headerId, imei);
                }
                continue;
            }

            if ("ICCID".equals(type)) {
                String imei = getValue(payload, 1);
                if (imei != null && !imei.isEmpty()) {
                    updateImeiMapping(headerId, imei);
                }
                continue;
            }

            if ("LK".equals(type)) {
                DeviceSession deviceSession = getDeviceSession(channel, remoteAddress, headerId);
                if (deviceSession == null) {
                    continue;
                }
                String imei = getMappedImei(headerId);
                if (imei != null) {
                    Position position = new Position(getProtocolName());
                    position.setDeviceId(deviceSession.getDeviceId());
                    position.setTime(new Date());
                    position.setValid(false);
                    position.set("headerId", headerId);
                    position.set("imei", imei);
                    positions.add(position);
                }
                continue;
            }

            if (!"UD_LTE".equals(type) && !"WT_LTE".equals(type)) {
                continue;
            }

            DeviceSession deviceSession = getDeviceSession(channel, remoteAddress, headerId);
            if (deviceSession == null) {
                continue;
            }

            Position position = new Position(getProtocolName());
            position.setDeviceId(deviceSession.getDeviceId());

            Date time = parseDateTime(getValue(payload, 0), getValue(payload, 1));
            position.setTime(time != null ? time : new Date());

            String valid = getValue(payload, 2);
            boolean validFix = "A".equalsIgnoreCase(valid);

            double latitude = parseCoordinate(getValue(payload, 3), getValue(payload, 4));
            double longitude = parseCoordinate(getValue(payload, 5), getValue(payload, 6));
            if (!Double.isNaN(latitude)) {
                position.setLatitude(latitude);
            }
            if (!Double.isNaN(longitude)) {
                position.setLongitude(longitude);
            }
            if (!Double.isNaN(latitude) && !Double.isNaN(longitude)) {
                validFix = true;
            }
            position.setValid(validFix);

            double speed = parseDouble(getValue(payload, 7));
            if (!Double.isNaN(speed)) {
                position.setSpeed(UnitsConverter.knotsFromKph(speed));
            }

            double course = parseDouble(getValue(payload, 8));
            if (!Double.isNaN(course)) {
                position.setCourse(course);
            }

            double altitude = parseDouble(getValue(payload, 9));
            if (!Double.isNaN(altitude)) {
                position.setAltitude(altitude);
            }

            position.set("headerId", headerId);
            String imei = getMappedImei(headerId);
            if (imei != null) {
                position.set("imei", imei);
            }

            setBatteryAndSignal(position, payload);

            int mcc = parseInt(getValue(payload, 18), Integer.MIN_VALUE);
            int mnc = parseInt(getValue(payload, 19), Integer.MIN_VALUE);
            int lac = parseInt(getValue(payload, 20), Integer.MIN_VALUE);
            int cid = parseInt(getValue(payload, 21), Integer.MIN_VALUE);
            if (mcc != Integer.MIN_VALUE) {
                position.set("mcc", mcc);
            }
            if (mnc != Integer.MIN_VALUE) {
                position.set("mnc", mnc);
            }
            if (lac != Integer.MIN_VALUE) {
                position.set("lac", lac);
            }
            if (cid != Integer.MIN_VALUE) {
                position.set("cid", cid);
            }

            int wifiIndex = findWifiIndex(payload);
            if (wifiIndex != -1) {
                position.set("wifiRaw", String.join(",", Arrays.copyOfRange(payload, wifiIndex, payload.length)));
            }

            positions.add(position);
        }

        if (positions.isEmpty()) {
            return null;
        }
        return positions.size() == 1 ? positions.get(0) : positions;
    }

    private List<String> extractFrames(String sentence) {
        List<String> frames = new ArrayList<>();
        int startIndex = sentence.indexOf('[');
        while (startIndex != -1) {
            int endIndex = sentence.indexOf(']', startIndex + 1);
            if (endIndex == -1) {
                break;
            }
            frames.add(sentence.substring(startIndex + 1, endIndex));
            startIndex = sentence.indexOf('[', endIndex + 1);
        }
        return frames;
    }

    private void updateImeiMapping(String headerId, String imei) {
        cleanupMappings();
        HEADER_TO_IMEI.put(headerId, new ImeiEntry(imei, System.currentTimeMillis()));
    }

    private String getMappedImei(String headerId) {
        cleanupMappings();
        ImeiEntry entry = HEADER_TO_IMEI.get(headerId);
        if (entry == null) {
            return null;
        }
        if (System.currentTimeMillis() - entry.lastUpdate > MAPPING_TIMEOUT) {
            HEADER_TO_IMEI.remove(headerId);
            return null;
        }
        return entry.imei;
    }

    private void cleanupMappings() {
        long now = System.currentTimeMillis();
        HEADER_TO_IMEI.entrySet().removeIf(entry -> now - entry.getValue().lastUpdate > MAPPING_TIMEOUT);
    }

    private String getValue(String[] payload, int index) {
        return index >= 0 && index < payload.length ? payload[index] : null;
    }

    private Date parseDateTime(String date, String time) {
        try {
            if (date == null || time == null || date.length() < 6 || time.length() < 6) {
                return null;
            }
            // FA66S LTE payload uses DDMMYY format (e.g. 190126 -> 19/01/2026).
            int day = parseInt(date.substring(0, 2), -1);
            int month = parseInt(date.substring(2, 4), -1);
            int year = parseInt(date.substring(4, 6), -1);
            int hour = parseInt(time.substring(0, 2), -1);
            int minute = parseInt(time.substring(2, 4), -1);
            int second = parseInt(time.substring(4, 6), -1);
            if (year < 0 || year > 99
                    || month < 1 || month > 12
                    || day < 1 || day > 31
                    || hour < 0 || hour > 23
                    || minute < 0 || minute > 59
                    || second < 0 || second > 59) {
                return null;
            }
            return new DateBuilder()
                    .setDate(2000 + year, month, day)
                    .setTime(hour, minute, second)
                    .getDate();
        } catch (NumberFormatException | IndexOutOfBoundsException ex) {
            return null;
        }
    }

    private double parseCoordinate(String value, String hemisphere) {
        double coordinate = parseDouble(value);
        if (Double.isNaN(coordinate)) {
            return Double.NaN;
        }
        if (hemisphere != null) {
            if (hemisphere.equalsIgnoreCase("S") || hemisphere.equalsIgnoreCase("W")) {
                coordinate = -Math.abs(coordinate);
            } else if (hemisphere.equalsIgnoreCase("N") || hemisphere.equalsIgnoreCase("E")) {
                coordinate = Math.abs(coordinate);
            }
        }
        return coordinate;
    }

    private int findWifiIndex(String[] payload) {
        for (int i = 0; i < payload.length; i++) {
            String value = payload[i];
            if (value != null && WIFI_PATTERN.matcher(value).matches()) {
                return i;
            }
        }
        return -1;
    }

    private int parseInt(String value, int defaultValue) {
        try {
            return value == null || value.isEmpty() ? defaultValue : Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            return defaultValue;
        }
    }

    private double parseDouble(String value) {
        try {
            return value == null || value.isEmpty() ? Double.NaN : Double.parseDouble(value);
        } catch (NumberFormatException ex) {
            return Double.NaN;
        }
    }

    private void setBatteryAndSignal(Position position, String[] payload) {
        Double batteryLevel = findPercentValue(payload, new int[] {12});
        if (batteryLevel != null) {
            position.set(Position.KEY_BATTERY_LEVEL, batteryLevel);
        }

        Double signal = findPercentValue(payload, new int[] {13});
        if (signal != null) {
            position.set("signal", signal);
        }
    }

    private Double findPercentValue(String[] payload, int[] indices) {
        for (int index : indices) {
            double value = parseDouble(getValue(payload, index));
            if (!Double.isNaN(value) && value >= 0 && value <= 100) {
                return value;
            }
        }
        return null;
    }

    private static class ImeiEntry {
        private final String imei;
        private final long lastUpdate;

        private ImeiEntry(String imei, long lastUpdate) {
            this.imei = imei;
            this.lastUpdate = lastUpdate;
        }
    }
}
