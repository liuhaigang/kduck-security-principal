package cn.kduck.security.principal.filter.extractor;

import cn.kduck.security.principal.AuthUser;
import cn.kduck.security.principal.filter.AuthUserExtractor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class SessionUserExtractorImpl implements AuthUserExtractor {
    @Override
    public AuthUser extract(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        AuthUser authUser = null;

        if(authentication instanceof UsernamePasswordAuthenticationToken){
            Object principal = authentication.getPrincipal();
            if(principal instanceof AuthUser){
                authUser = (AuthUser)principal;
//                    if(userExtInfo != null) {
//                        ValueMap userExtInfo = this.userExtInfo.getUserExtInfo(authUser.getUsername());
//                        authUser.setAllDetailsItem(userExtInfo);
//                    }
//                    AuthUserContext.setAuthUser(authUser);

            } else if (principal instanceof UserDetails){
                UserDetails userDetails = (UserDetails)principal;

                Collection<? extends GrantedAuthority> grantedAuthorities = userDetails.getAuthorities();
                List<String> authorities = new ArrayList<>(grantedAuthorities.size());
                if(grantedAuthorities != null){
                    for (GrantedAuthority authority : grantedAuthorities) {
                        authorities.add(authority.getAuthority());
                    }
                }

                authUser = new AuthUser(userDetails.getUsername(),
                        userDetails.isEnabled(),
                        userDetails.isAccountNonExpired(),
                        userDetails.isCredentialsNonExpired(),
                        userDetails.isAccountNonLocked(),
                        authorities);
            } else {
                throw new IllegalArgumentException("无法识别的认证对象：" + principal);
            }
        }

        return authUser;
    }
}
