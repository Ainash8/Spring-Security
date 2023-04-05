package com.springboot.security.SpringSecurity.filter;

import com.springboot.security.SpringSecurity.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class SecurityFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        //1.Read token from authorization request
        String token = request.getHeader("Authorization");
        if(token != null){
            String username = jwtUtil.getUsername(token);
            //username should not be empty, context auth must be empty
            if(username !=null && SecurityContextHolder.getContext().getAuthentication()==null){
                UserDetails usr = userDetailsService.loadUserByUsername(username);
                //validate token
                boolean isValid = jwtUtil.validateToken(token,usr.getUsername());
                if(isValid){
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username,usr.getPassword(),usr.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    //final object stored in security context with user details (username, pwd)
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                }

            }
        }

    }
}
