package com.security.security.websecurity;

import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class AuthorizationFilter extends BasicAuthenticationFilter {
    public AuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String token = request.getHeader(SecurityConstants.REQUEST_HEADER);

        if (token == null || !token.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(request);

        System.out.println("Authorities: " + authentication.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(SecurityConstants.REQUEST_HEADER);

        if (token != null) {
            token = token.replace(SecurityConstants.TOKEN_PREFIX, "");

            String user = Jwts.parser()
                    .setSigningKey(SecurityConstants.JWT_SECRET_TOKEN)
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();

            String role = Jwts.parser()
                    .setSigningKey(SecurityConstants.JWT_SECRET_TOKEN)
                    .parseClaimsJws(token)
                    .getBody()
                    .getAudience();

            if (user != null && role != null) {
                Collection<GrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority(role.substring(1, role.length() - 1)));
                return new UsernamePasswordAuthenticationToken(user, null, authorities);
            }

            return null;
        }

        return null;
    }
}
