package com.ltp.gradesubmission.service;


import com.ltp.gradesubmission.entity.User;

public interface UserService {
    User getUser(Long id);
    void saveUser(User user);
    User getUser(String username);
}