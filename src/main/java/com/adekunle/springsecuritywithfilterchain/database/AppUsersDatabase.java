package com.adekunle.springsecuritywithfilterchain.database;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@RequiredArgsConstructor
@Repository
public class AppUsersDatabase {

  //  private static final BCryptPasswordEncoder passwordEncoder = null;

    public static List<UserDetails> appUsers;

    static {
      //  assert passwordEncoder != null;
        appUsers = Arrays.asList(
                new User("adekunle@gmail.com","1234",
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN"))),
                new User("james@gmail.com","1234",
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))),
                new User("richy2@gmail.com",
                        "1234",
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN"))),
                new User("martina@gmail.com",
                        "1234",
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")))
        );
    }

    public UserDetails findByEmail(String email) {
        return AppUsersDatabase.appUsers.stream()
                .filter(u -> u.getUsername().equals(email))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("User not found exception"));
    }
}
