#ifndef YUKIZYGISK_HOST_INODE_H
#define YUKIZYGISK_HOST_INODE_H

struct inode;
struct inode_security_struct;
struct lsm_blob_sizes;

int yz_selinux_inode_init(const struct lsm_blob_sizes *blob_sizes);
struct inode_security_struct *yz_selinux_inode(const struct inode *inode);

#endif
