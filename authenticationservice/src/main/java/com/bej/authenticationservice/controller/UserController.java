package com.bej.authenticationservice.controller;

import com.bej.authenticationservice.domain.User;
import com.bej.authenticationservice.exception.UserAlreadyExistsException;
import com.bej.authenticationservice.exception.UserNotFoundException;
import com.bej.authenticationservice.service.SecurityTokenGenerator;
import com.bej.authenticationservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class UserController {
    private UserService userService;
    private ResponseEntity responseEntity;
    private SecurityTokenGenerator securityTokenGenerator;

    @Autowired
    public UserController(UserService userService,SecurityTokenGenerator securityTokenGenerator){
        this.userService = userService;
        this.securityTokenGenerator = securityTokenGenerator;
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody User user) throws UserNotFoundException{
        Map<String,String> map = null;
        try{
            User userObj = userService.findByUserNameAndPassword(user.getUserName(),user.getUserPassword());
            if(userObj.getUserName().equals(user.getUserName())){
                map = securityTokenGenerator.generateToken(user);
            }
            responseEntity = new ResponseEntity<>(map, HttpStatus.OK);
        } catch(UserNotFoundException e){
            throw new UserNotFoundException();
        } catch(Exception e){
            responseEntity = new ResponseEntity<>("Try after Some time!!!",HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return responseEntity;
    }

    @PostMapping("/register")
    public ResponseEntity<?> saveUser(@RequestBody User user) throws UserAlreadyExistsException{
      User createdUser = userService.saveUser(user);
      return responseEntity = new ResponseEntity<>("User Created",HttpStatus.OK);
    }

    @GetMapping("/read")
    public ResponseEntity<?> getAllUser() {
        List<User> list = userService.getAllUser();
        responseEntity = new ResponseEntity<>(list,HttpStatus.OK);
        return responseEntity;
    }

    @DeleteMapping("/user/{userId}")
    public ResponseEntity<?> delete(@PathVariable int userId) throws UserNotFoundException{
       try{
           userService.deleteUser(userId);
       } catch(UserNotFoundException e){
           throw new UserNotFoundException();
       }
       return new ResponseEntity<>("User Deleted successfully.",HttpStatus.OK);
    }
}
