package com.bej.authenticationservice.service;

import com.bej.authenticationservice.domain.User;
import com.bej.authenticationservice.exception.UserAlreadyExistsException;
import com.bej.authenticationservice.exception.UserNotFoundException;

import java.util.List;

public interface UserService {
    User saveUser(User user) throws UserAlreadyExistsException;
    User findByUserNameAndPassword(String userName,String userPassword) throws UserNotFoundException;
    List<User> getAllUser();
    boolean deleteUser(int userId) throws UserNotFoundException;
}
