package com.phishguard.repository;

import com.phishguard.entity.ScanHistory;
import com.phishguard.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ScanHistoryRepository extends JpaRepository<ScanHistory, Long> {

    Page<ScanHistory> findByUserOrderByCreatedAtDesc(User user, Pageable pageable);

    Page<ScanHistory> findAllByOrderByCreatedAtDesc(Pageable pageable);

    long countByLevel(String level);

    @Query("SELECT sh.domain, COUNT(sh) as cnt FROM ScanHistory sh WHERE sh.level IN ('suspicious','dangerous') " +
           "GROUP BY sh.domain ORDER BY cnt DESC")
    List<Object[]> findMostTargetedDomains(Pageable pageable);

    List<ScanHistory> findTop10ByLevelOrderByCreatedAtDesc(String level);
}
