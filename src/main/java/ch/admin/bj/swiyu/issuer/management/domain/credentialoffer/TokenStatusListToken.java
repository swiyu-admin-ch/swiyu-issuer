/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.management.common.exception.ConfigurationException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterOutputStream;

/**
 * See <a href=
 * "https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#name-status-list-token-in-jwt-fo">spec</a>
 * Status List published on registry
 */
@Slf4j
@Getter
public class TokenStatusListToken {

    /**
     * Indicator how many consecutive bits of the token status list are contained
     * within one status list entry.
     * Can be 1, 2, 4 or 8
     * bit 0x1 is always revocation
     * bit 0x2 is always suspension (if available)
     */
    private final int bits;
    /**
     * zlib zipped & url encoded bytes containing the status information
     */
    private final byte[] statusList;

    /**
     * Creates a new empty token status list
     *
     * @param bits             how many bits each status list entry shall have
     * @param statusListLength the number of status list entries available
     */
    public TokenStatusListToken(int bits, int statusListLength) {
        this.bits = bits;
        statusList = new byte[statusListLength];
    }

    /**
     * Load existing TokenStatusList Token
     *
     * @param bits       how many bits each status list entry has
     * @param statusList the data of the existing status list entry
     */
    public TokenStatusListToken(int bits, byte[] statusList) {
        this.bits = bits;
        this.statusList = statusList;
    }

    public static TokenStatusListToken loadTokenStatusListToken(int bits, String lst) throws IOException {
        return new TokenStatusListToken(bits, decodeStatusList(lst));
    }

    private static String encodeStatusList(byte[] statusList) {
        // zipping the data
        try {
            var zlibOutput = new ByteArrayOutputStream();
            var deflaterStream = new DeflaterOutputStream(zlibOutput, new Deflater(9));
            deflaterStream.write(statusList);
            deflaterStream.finish();
            byte[] clippedZlibOutput = Arrays.copyOf(zlibOutput.toByteArray(), zlibOutput.size());
            deflaterStream.close();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(clippedZlibOutput);
        } catch (IOException e) {
            log.error("Error occurred during zipping of Status List data", e);
            throw new ConfigurationException("Status List data can not be zipped");
        }
    }

    /**
     * @param lst
     * @return the bytes of the status list
     * @throws DataFormatException if the lst is not a zlib compressed status list
     */
    private static byte[] decodeStatusList(String lst) throws IOException {
        // base64 decoding the data
        byte[] zippedData = Base64.getUrlDecoder().decode(lst);

        var zlibOutput = new ByteArrayOutputStream();
        var inflaterStream = new InflaterOutputStream(zlibOutput);
        inflaterStream.write(zippedData);
        inflaterStream.finish();
        byte[] clippedZlibOutput = Arrays.copyOf(zlibOutput.toByteArray(), zlibOutput.size());
        inflaterStream.close();
        return clippedZlibOutput;

    }

    /**
     * Claims to be put in the status_list property
     *
     * @return a claim set containing
     */
    public Map<String, Object> getStatusListClaims() {
        return Map.of("bits", bits, "lst", encodeStatusList(statusList));
    }

    public String getStatusListData() {
        return encodeStatusList(statusList);
    }

    /**
     * Retrieves the status on the given index.
     * 0 = Valid
     * 1 = Revoked
     * 2 = Suspended
     * 3 = ApplicationSpecificStatus#1
     * ...
     *
     * @param idx index of the status list entry
     * @return the status bits as an integer
     */
    public int getStatus(int idx) {
        byte entryByte = getStatusEntryByte(idx);
        // The starting position of the status in the Byte
        var bitIndex = (idx * bits) % 8;
        // Mask to remove all bits larger than the status
        var mask = (1 << bitIndex << bits) - 1;
        // Drop all bits larger than our status
        var maskedByte = entryByte & mask;
        // Shift the status to the start of the byte so 1 = revoked, 2 = suspended, etc,
        // also removes all bits smaller than our status
        var vcStatus = maskedByte >> bitIndex;
        return vcStatus;
    }

    /**
     * Sets status bit to active
     *
     * @param idx    index of the status list entry
     * @param status The new status to be set
     */
    public void setStatus(int idx, int status) {
        verifyStatusArgument(status);
        unsetStatus(idx);
        byte entryByte = getStatusEntryByte(idx);
        entryByte |= getBitPosition(idx, status);
        setStatusEntryByte(idx, entryByte);
    }

    /**
     * Sets status to 0
     *
     * @param idx index of the status list entry
     */
    public void unsetStatus(int idx) {
        int status = (1 << bits) - 1;
        verifyStatusArgument(status);
        byte entryByte = getStatusEntryByte(idx);
        // Shift the bit to the correct position in the byte
        entryByte &= ~getBitPosition(idx, status);
        setStatusEntryByte(idx, entryByte);
    }

    public boolean canRevoke() {
        return bits >= TokenStatsListBit.REVOKE.getValue();
    }

    public boolean canSuspend() {
        return bits >= TokenStatsListBit.SUSPEND.getValue();
    }

    /**
     * Moves the status bit to the correct position in a byte
     * eg. with bits=2 and index 1 will move a status of 1 to
     * 0b00000100
     *
     * @param idx    index of the entry
     * @param status a status bit
     * @return the status bit moved to the position in a byte
     */
    private int getBitPosition(int idx, int status) {
        return status << (idx * bits) % 8;
    }

    private void verifyStatusArgument(int status) {
        if (1 << bits <= status) {
            throw new IllegalArgumentException(
                    "Status can not exceed bits but was %d while expecting maximum of %d".formatted(status, bits));
        }
    }

    private byte getStatusEntryByte(int idx) {
        return statusList[idx * bits / 8];
    }

    /**
     * Warning, this sets the whole byte, can therefore also affect neighbouring
     * statuses if statusValue is incorrect
     *
     * @param idx
     * @param statusValue the bytes from getStatusEntryByte but modified
     */
    private void setStatusEntryByte(int idx, byte statusValue) {
        statusList[idx * bits / 8] = statusValue;
    }

}
