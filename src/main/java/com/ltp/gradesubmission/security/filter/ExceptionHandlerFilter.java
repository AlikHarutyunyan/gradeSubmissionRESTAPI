package com.ltp.gradesubmission.security.filter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.ltp.gradesubmission.exception.EntityNotFoundException;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ExceptionHandlerFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try{
            filterChain.doFilter(request,response);
        }
        catch(EntityNotFoundException e){
            exceptionMessageBuilder(response,HttpServletResponse.SC_NOT_FOUND,"the username doesn't exist");
        }
        catch (JWTVerificationException e){
            exceptionMessageBuilder(response,HttpServletResponse.SC_UNAUTHORIZED,"incorrect jwt");
        }
        catch (RuntimeException e) {
            exceptionMessageBuilder(response,HttpServletResponse.SC_BAD_REQUEST,"the username or the password is incorrect");
        }
    }

    private void exceptionMessageBuilder(HttpServletResponse response, int code, String message) throws IOException {
        response.setStatus(code);
        response.getWriter().write(message);
        response.getWriter().flush();
    }
}
