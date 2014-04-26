/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/
#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR
#define MYDATA ((myfs_state *) fuse_get_context()->private_data)
#define ENCRYPTED "user.pa4-encfs.encrypted"



#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
/* For open_memstream() */
#define _POSIX_C_SOURCE 200809L
#endif
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <linux/limits.h>
#include <ctype.h>
#include <libgen.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#include <sys/types.h>
#endif

#include "aes-crypt.h"

#define PASSPHRASE "turtle"
#define ENCRYPT 1
#define DECRYPT 0


#define SUFFIXGETATTR ".getattr"
#define SUFFIXREAD ".read"
#define SUFFIXWRITE ".write"
#define SUFFIXCREATE ".create"
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif



//int do_crypt(FILE* in, FILE* out, int action, char* key_str);
//Initialize my private data struct.
typedef struct{
    char *rootdir;
    char *passphrase;
}myfs_state;

static void xmp_fullpath(char fpath[PATH_MAX], const char *path)
{
    strcpy(fpath, MYDATA->rootdir);
    strncat(fpath, path, PATH_MAX); // ridiculously long paths will break here
				    
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	int res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	int res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */
//mapping/jump table of bfs functions 
//map to system calls

static int is_encrypted(const char *path){
	ssize_t valuelength;
	char* value;
	
	//get the length of the memory space for the attribute
	valuelength = xmp_getxattr(path, "user.encrypted", NULL, 0);
	if (valuelength < 0) { 
		return -errno;
	}
	
	//allocate space for the value
	value = malloc(sizeof(*value)*(valuelength+1));
	
	//get the value of the attribute
	
	valuelength = xmp_getxattr(path, ENCRYPTED, value, valuelength);

    value[valuelength] = '\0';
	
	//check if it is encrypted
	if (!strcmp(value, "true")){
		return 1;
	}
	return 0;
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;
    char fpath[PATH_MAX];
    char *memdata;
    size_t memsize;
	xmp_fullpath(fpath, path);
	FILE* memfp;
	int memfd;
	FILE* fp;
	
	if (is_encrypted(fpath) == 1){
	//want to decrypt the file so we can return the decrypted attribute
	fp = fopen(fpath, "r");
	if (fp == NULL)
		return -errno;
		
	//memstream sets the values for data and size
	//opens a stream of memory for us to access
	memfp = open_memstream(&memdata, &memsize);
	if (memfp == NULL)
		return -errno;
		
	//decrypt the file, and store it in that memory stream so we can read it
	do_crypt(fp, memfp, DECRYPT, MYDATA->passphrase);
	//close the file on disk, done reading it
	fclose(fp);
	
	//wait until file is done being written to memory
	//fseek, travel to the offset of the file to begin reading
	fflush(memfp);
	
	//Get the file descriptor from the file pointer memfp
	memfd = fileno(memfp);
	
	//find the attribute from the decrypted file in the memorystream
	res = fstat(memfd, stbuf);
	}
	else res = lstat(fpath, stbuf);

	
	if (res == -1)
		return -errno;

	return 0;

}

static int xmp_access(const char *path, int mask)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	
	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	
	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	dp = opendir(fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fpath, mode);
	else
		res = mknod(fpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	
	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}
//Added support for encryption
static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	FILE *fp, *memfp;
	char *memdata;
	size_t memsize;
	int res;
	//Updates path to full directory path
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	(void) fi;
	//open the file we want to read
	fp = fopen(fpath, "r");
	if (fp == NULL)
		return -errno;
		
	//check if the file is encrypted, decrypt if it is	
	if(is_encrypted(fpath)){
		
	//memstream sets the values for data and size
	//opens a stream of memory for us to access
	memfp = open_memstream(&memdata, &memsize);
	if (memfp == NULL)
		return -errno;
		
	//decrypt the file, and store it in that memory stream so we can read it
	do_crypt(fp, memfp, DECRYPT, MYDATA->passphrase);
	
	
	//wait until file is done being written to memory
	//fseek, travel to the offset of the file to begin reading
	fflush(memfp);
	fseek(memfp, offset, SEEK_SET);
	
	//read data elements into buffer from memorystream
	res = fread(buf, 1, size, memfp);
	if (res == -1)
		res = -errno;
		
	//close memory stream, read complete

	fclose(memfp);
}
	else res = fread(buf, 1, size, fp);
	
	//close the file on disk, done reading it
	fclose(fp);
	return res;
}
//Added support for encryption
static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
    FILE *fp, *memfp;
	int res;
    char *memdata;
    size_t memsize;
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	(void) fi;
	//open file we want to write to
    fp = fopen(fpath, "r");
	if (fp == NULL) 
        return -errno; 
    
    //check if the file is encrypted, encrypt if it is	
	if(is_encrypted(fpath)){
		
	//create a memorystream for the file, we will first decrypt and read
    memfp = open_memstream(&memdata, &memsize);
	if (memfp == NULL)
		return -errno;
	
	//decrypt the file we want to write to, put the decrypted file in the memory
	//stream for safekeeping, close the file
    do_crypt(fp, memfp, DECRYPT, PASSPHRASE);

    fclose(fp);

	//travel to the offset we want to write to in the file located in memory stream
    fseek(memfp, offset, SEEK_SET);
    res = fwrite(buf, 1, size, memfp);
	if (res == -1)
		return -errno;
    fflush(memfp);
	
	//open the file, we will do our write now
	//travel to the offset of the decrypted file
	//encrypt the in-stream file and store it in it's original location
    fp = fopen(fpath, "w");
    fseek(memfp, 0, SEEK_SET);
    do_crypt(memfp, fp, ENCRYPT, PASSPHRASE);

	//close the memorystream that held the file, close the file
    fclose(memfp);
	}
	else res = fwrite(buf, 1, size, fp);
    fclose(fp);


	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
//added encryption support for creating a file
    (void) fi;
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

    int res = creat(fpath, mode);
    if(res == -1)
	return -errno;
	
	//get the file pointer we created and encrypt the file
	FILE* newres = fdopen(res, "w");
	close(res);
	int crypt = do_crypt(newres, newres, ENCRYPT, PASSPHRASE);
	if(crypt == FAILURE)
		return -errno;
		
	fclose(newres);

	//create the encrypted flag to mark the file as encrypted at creation
	xmp_setxattr(fpath, ENCRYPTED, "true", 4, 0);
	
    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	(void) fpath;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	(void) fpath;
	(void) isdatasync;
	(void) fi;
	return 0;
}


static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create         = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	myfs_state *myfsData;
	umask(0);
	if ((argc < 4) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-')){
		printf("Usage: <mount directory> <mount point> <encryption keyphrase> \n");
		return 1;
	}
	
    myfsData = malloc(sizeof(myfs_state));
    if (myfsData == NULL) {
		perror("main calloc");
		abort();
    }

    // Pull the rootdir out of the argument list and save it in my
    // internal data
    myfsData->rootdir = realpath(argv[argc-3], NULL);
    myfsData->passphrase = strncpy(argv[argc-1],argv[argc-1],256);
    argv[argc-3] = argv[argc-1];
    argv[argc-1] = NULL;
    argc--;
    argv[argc-2] = argv[argc-1];
    argv[argc-1] = NULL;
    argc--;

	return fuse_main(argc, argv, &xmp_oper, myfsData);
}
