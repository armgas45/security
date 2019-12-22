package com.security.security.service;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends CrudRepository<RoleEntity, Long> {
    RoleEntity findByUsernameAndPassword(String username, String password);
}
