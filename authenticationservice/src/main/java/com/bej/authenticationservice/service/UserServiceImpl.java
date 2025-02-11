package com.bej.authenticationservice.service;

import com.bej.authenticationservice.domain.User;
import com.bej.authenticationservice.exception.UserAlreadyExistsException;
import com.bej.authenticationservice.exception.UserNotFoundException;
import com.bej.authenticationservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImpl implements UserService {
    private UserRepository userRepository;


    @Autowired
    public UserServiceImpl(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    @Override
    public User saveUser(User user) throws UserAlreadyExistsException {
       if(userRepository.findById(user.getUserId()).isPresent()){
           throw new UserAlreadyExistsException();
       }
        return userRepository.save(user);

    }

    @Override
    public User findByUserNameAndPassword(String userName,String userPassword) throws UserNotFoundException{
        User user = userRepository.findUserByUserNameAndUserPassword(userName,userPassword);
        if(user == null){
            throw new UserNotFoundException();
        }
        return user;
    }

    @Override
    public List<User> getAllUser(){
        return userRepository.findAll();
    }

    @Override
    public boolean deleteUser(int userId) throws UserNotFoundException{
        if(userRepository.findById(userId).isPresent()){
            userRepository.deleteById(userId);
            return true;
        }else{
            throw new UserNotFoundException();
        }
    }
}
