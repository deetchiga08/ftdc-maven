package com.briller.service;

import com.briller.model.Users;
import com.briller.repository.UserRepository;
import com.briller.utility.TokenUtility;
import io.micrometer.core.instrument.util.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class UserService {

    @Autowired
    @Qualifier(value = "passwordEncoder")
    PasswordEncoder passwordEncoder;

    @Autowired
    UserRepository userRepository;

    @Value("${briller.secret}")
    private String applicationSecret;


    @Autowired
    private TokenUtility tokenUtility;



    public boolean registerUser(Users user) throws Exception {
        if (userExists(user.getUserName())) {
            throw new Exception();
        }
        if (!StringUtils.isEmpty(user.getUserName()) && !StringUtils.isEmpty(user.getPassword())) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            if (isValidEmail(user.getUserName())) {
                user.setEmail(user.getUserName());
            } else {
                user.setPhoneNbr(user.getUserName());
            }
            String token = createToken(user, false);
            user.setToken("1");

            //Optional.ofNullable(roleService.retrieveRoleIfExists(user.getRole())).ifPresent(role -> user.setRole(role));

            userRepository.save(user);

        }

        return true;
    }
    private boolean userExists(String userName){
        if(!StringUtils.isEmpty(userName)){
            Optional<Users>  usersOptional = userRepository.findByUserName(userName);
            return usersOptional.isPresent();
        }
        return false;
    }

    /**
     * createToken
     * @param user User
     * @param save Boolean
     * @return String
     */
    public String createToken(Users user, Boolean save) {
        String userName= user.getUserName();
        String token = isValidEmail(userName)?passwordEncoder.encode(applicationSecret+userName):tokenUtility.generatePhoneToken();
        if (save) {
            user.setToken(token);
            this.userRepository.save(user);
        }
        return token;
    }

    /**
     * isValidEmail
     * @param email String
     * @return matchFound boolean
     */
    public boolean isValidEmail(String email) {
        boolean matchFound;
        Pattern p = Pattern.compile(".+@.+\\.[a-z]+");
        Matcher m = p.matcher(email);
        matchFound = m.matches();
        return matchFound;
    }

}
