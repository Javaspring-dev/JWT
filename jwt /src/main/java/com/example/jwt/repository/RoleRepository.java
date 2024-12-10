package com.example.jwt.repository;

import com.example.jwt.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface RoleRepository extends JpaRepository<Role,Long>
{
    Optional<Role>findByName(String name);
}
