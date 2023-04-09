package com.boot.security.repository;

import com.boot.security.domain.Account;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;

public interface UserRepository extends JpaRepository<Account,Long> {

}
