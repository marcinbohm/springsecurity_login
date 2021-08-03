package com.example.sprsecurity.auth;

import java.util.Optional;

public interface ApplicationUserDAO {

    Optional<ApplicationUser> selectAplicationUserByUsername(String username);
}
