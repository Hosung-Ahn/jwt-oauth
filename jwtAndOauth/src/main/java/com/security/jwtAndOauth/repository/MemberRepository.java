package com.security.jwtAndOauth.repository;

import com.security.jwtAndOauth.domain.Member;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface MemberRepository extends CrudRepository<Member, Long> {
    Member findByEmail(String email);

    boolean existsByEmail(String email);
}
