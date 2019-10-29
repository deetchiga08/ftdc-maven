package com.briller.service;

import com.briller.model.FtdcUserDetails;
import com.briller.model.Users;
import com.briller.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Users> optionalUsers = userRepository.findByUserName(username);
        optionalUsers.orElseThrow(() -> new UsernameNotFoundException("Username not found"));
        return optionalUsers.map(FtdcUserDetails::new).get();
    }
}
