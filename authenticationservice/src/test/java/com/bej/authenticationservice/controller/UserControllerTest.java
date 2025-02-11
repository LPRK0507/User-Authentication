package com.bej.authenticationservice.controller;

import com.bej.authenticationservice.domain.User;
import com.bej.authenticationservice.exception.UserAlreadyExistsException;
import com.bej.authenticationservice.service.UserServiceImpl;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
public class UserControllerTest {

    private MockMvc mockMvc;
    @Mock
    private UserServiceImpl userService;

    @InjectMocks
    private UserController userController;

    private User user1,user2;
    List<User> list;

    @BeforeEach
    void setUp(){
        user1 = new User(1,"Ashok","Pass@112","Bangalore");
        user2 = new User(2,"Kumar","Pass@123","Hyderabad");
        list = Arrays.asList(user1,user2);

        mockMvc = MockMvcBuilders.standaloneSetup(userController).build();
    }

    @AfterEach
    void tearDown(){
        user1 = null;
        user2 = null;
    }


    @Test
    public void givenUserToSaveAndReturnSavedUserSuccess() throws Exception {
        when(userService.saveUser(any())).thenReturn(user1);
        mockMvc.perform(post("/api/v1/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(jsonToString(user1)))
                .andExpect(status().isOk()).andDo(MockMvcResultHandlers.print());
        verify(userService,times(1)).saveUser(any());
    }

    @Test
    public void givenUserToSaveAndReturnSavedUserFailure() throws Exception{
        when(userService.saveUser(any())).thenThrow(UserAlreadyExistsException.class);
        mockMvc.perform(post("/api/v1/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(jsonToString(user1)))
                .andExpect(status().isConflict()).andDo(MockMvcResultHandlers.print());
        verify(userService,times(1)).saveUser(any());
    }

    @Test
    public void givenUserToDeleteAndDeleteSuccess() throws Exception{
        when(userService.deleteUser(anyInt())).thenReturn(true);
        mockMvc.perform(delete("/api/v1/user/1")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()).andDo(MockMvcResultHandlers.print());
        verify(userService,times(1)).deleteUser(anyInt());
    }


    private static String jsonToString (final Object object) throws JsonProcessingException{
        String result;
        try{
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonContent = objectMapper.writeValueAsString(object);
            result = jsonContent;
        } catch(JsonProcessingException e){
            result = "Json processing error";
        }
        return result;
    }
}
