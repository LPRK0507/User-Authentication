package com.bej.authenticationservice.service;

import com.bej.authenticationservice.domain.User;
import com.bej.authenticationservice.exception.UserAlreadyExistsException;
import com.bej.authenticationservice.exception.UserNotFoundException;
import com.bej.authenticationservice.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.internal.matchers.NotNull;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserServiceTest {
    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserServiceImpl userService;

    private User user1,user2;
    List<User> list;

    @BeforeEach
    void setUp(){
        user1 = new User(1,"Ashok","pass123","bangalore");
        user2 = new User(2,"Ram","pass@12","Chennai");
        list = Arrays.asList(user1,user2);
    }

    @AfterEach
    void tearDown(){
        user1 = null;
        user2 = null;
    }

    @Test
   public void givenUserToSaveAndReturnSavedUserSuccess() throws UserAlreadyExistsException{
        when(userRepository.findById(user1.getUserId())).thenReturn(Optional.ofNullable(null));
        when(userRepository.save(any())).thenReturn(user1);
        assertEquals(user1,userService.saveUser(user1));
        verify(userRepository,times(1)).save(any());
        verify(userRepository,times(1)).findById(any());
    }

    @Test
    public void givenUserToSaveAndReturnSavedUserFailure(){
        when(userRepository.findById(user1.getUserId())).thenReturn(Optional.ofNullable(user1));
        assertThrows(UserAlreadyExistsException.class,()->userService.saveUser(user1));
        verify(userRepository,times(0)).save(any());
        verify(userRepository,times(1)).findById(any());
    }

    @Test
    public void givenUserToDeleteShouldDeleteSuccess() throws UserNotFoundException{
        when(userRepository.findById(user1.getUserId())).thenReturn(Optional.ofNullable(user1));
        boolean flag = userService.deleteUser(user1.getUserId());
        assertEquals(true,flag);
        verify(userRepository,times(1)).deleteById(any());
        verify(userRepository,times(1)).findById(any());
    }

}
