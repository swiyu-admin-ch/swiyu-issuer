package ch.admin.bit.eid.issuer_management.interceptor;

import com.google.gson.JsonParser;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequestWrapper;
import lombok.Getter;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.ParseException;
import java.util.stream.Collectors;

@Getter
public class JWTResolveRequestWrapper extends HttpServletRequestWrapper {
    private final SignedJWT jwt;
    private final String dataClaim;
    public JWTResolveRequestWrapper(HttpServletRequestWrapper request) throws IOException, ParseException {
        super(request);
        String jwtString = request.getReader().lines().collect(Collectors.joining());
        this.jwt = SignedJWT.parse(jwtString);
        this.dataClaim = JsonParser.parseString(jwt.getJWTClaimsSet().getStringClaim("data")).toString();

    }

    @Override
    public ServletInputStream getInputStream() {
        final ByteArrayInputStream buffer = new ByteArrayInputStream(dataClaim.getBytes());
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return buffer.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                throw new RuntimeException("Not implemented");
            }

            @Override
            public int read() {
                return buffer.read();
            }
        };
    }

    @Override
    public BufferedReader getReader() throws IOException {
        return new BufferedReader(new InputStreamReader(getInputStream()));
    }
}
