package ch.admin.bj.swiyu.issuer.infrastructure.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Component
public class FormFieldRenamingFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        if (!Objects.equals(httpRequest.getContentType(), MediaType.APPLICATION_FORM_URLENCODED_VALUE)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequestWrapper wrappedRequest = new HttpServletRequestWrapper(httpRequest) {
            @Override
            public Map<String, String[]> getParameterMap() {
                return super.getParameterMap().entrySet().stream()
                        .collect(Collectors.toMap(entry -> entry.getKey().replace("-", ""), Map.Entry::getValue));
            }

            @Override
            public String getParameter(String name) {
                return getParameterMap().getOrDefault(name, new String[]{null})[0];
            }

            @Override
            public String[] getParameterValues(String name) {
                return getParameterMap().get(name);
            }
        };

        chain.doFilter(wrappedRequest, response);
    }
}