package com.briller.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.Date;

@Getter
@Setter
@Entity
public class Role {

    private int roleId;
    private String type;
    private String description;
    private String createdBy;
    private String updatedBy;
    private LocalDateTime createdDt;
    private LocalDateTime updatedDt;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "role_id")
    public int getRoleId() {
        return roleId;
    }

    public void setRoleId(int roleId) {
        this.roleId = roleId;
    }

    @Basic
    @Column(name = "type", nullable = false)
    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    @Basic
    @Column(name = "description")
    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Basic
    @Column(name = "created_by")
    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    @Basic
    @Column(name = "updated_by")
    public String getUpdatedBy() {
        return updatedBy;
    }

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy;
    }

    @Basic
    @Column(name = "created_dt")
    @CreatedDate
    public LocalDateTime getCreatedDt() {
        return createdDt;
    }

    public void setCreatedDt(LocalDateTime createdDt) {
        this.createdDt = createdDt;
    }

    @Basic
    @Column(name = "updated_dt")
    @LastModifiedDate
    public LocalDateTime getUpdatedDt() {
        return updatedDt;
    }

    public void setUpdatedDt(LocalDateTime updatedDt) {
        this.updatedDt = updatedDt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Role role = (Role) o;

        if (type != null ? !type.equals(role.type) : role.type != null) return false;
        if (description != null ? !description.equals(role.description) : role.description != null) return false;
        if (createdBy != null ? !createdBy.equals(role.createdBy) : role.createdBy != null) return false;
        if (updatedBy != null ? !updatedBy.equals(role.updatedBy) : role.updatedBy != null) return false;
        if (createdDt != null ? !createdDt.equals(role.createdDt) : role.createdDt != null) return false;
        if (updatedDt != null ? !updatedDt.equals(role.updatedDt) : role.updatedDt != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = type.hashCode();
        result = 31 * result + (description != null ? description.hashCode() : 0);
        result = 31 * result + (createdBy != null ? createdBy.hashCode() : 0);
        result = 31 * result + (updatedBy != null ? updatedBy.hashCode() : 0);
        result = 31 * result + (createdDt != null ? createdDt.hashCode() : 0);
        result = 31 * result + (updatedDt != null ? updatedDt.hashCode() : 0);
        return result;
    }
}
