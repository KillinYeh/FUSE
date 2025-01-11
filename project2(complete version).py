from __future__ import with_statement
import os
import sys
import errno
import json
from fuse import FUSE, FuseOSError, Operations
from cryptography.fernet import Fernet   # 用於加密和解密
class EncryptedPassthrough(Operations):
    def __init__(self, root, key,key_path):
        self.root = root  # 來源目錄
        # 檢查 key.json 是否存在
        self.key_path = key_path
        if os.path.exists(self.key_path) and os.path.getsize(self.key_path) > 0:
            with open(self.key_path, 'r') as f:
                print("find json ")
                self.key= json.load(f)
        else:
            print("empty file")
            self.key={}  # 如果檔案不存在或是空檔案，初始化為空字典

    def _full_path(self, partial):
        # 生成來源目錄的完整路徑
        partial = partial.lstrip("/")
        return os.path.join(self.root, partial)

    # Filesystem methods
    def access(self, path, mode):
        full_path = self._full_path(path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def chmod(self, path, mode):
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        st = os.lstat(full_path)
        return dict((key, getattr(st, key)) for key in (
            'st_atime', 'st_ctime', 'st_gid', 'st_mode', 'st_mtime',
            'st_nlink', 'st_size', 'st_uid'))

    def readdir(self, path, fh):
        full_path = self._full_path(path)
        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for entry in dirents:
            yield entry

    def readlink(self, path):
        # 處理符號鏈接
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            return os.path.relpath(pathname, self.root)  # 返回相對路徑
        else:
            return pathname

    def mknod(self, path, mode, dev):
        # 創建文件節點
        return os.mknod(self._full_path(path), mode, dev)

    def rmdir(self, path):
        # 刪除目錄
        full_path = self._full_path(path)
        return os.rmdir(full_path)

    def mkdir(self, path, mode):
        # 創建目錄
        return os.mkdir(self._full_path(path), mode)

    def statfs(self, path):
        # 獲取文件系統狀態
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
                                                         'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files',
                                                         'f_flag',
                                                         'f_frsize', 'f_namemax'))

    def unlink(self, path):
        # 刪除文件
        return os.unlink(self._full_path(path))

    def symlink(self, name, target):
        # 創建符號鏈接
        return os.symlink(name, self._full_path(target))

    def rename(self, old, new):
        # 重命名文件或目錄
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        # 創建硬鏈接
        return os.link(self._full_path(target), self._full_path(name))

    def utimens(self, path, times=None):
        # 更改文件的訪問和修改時間
        return os.utime(self._full_path(path), times)

    # File methods
    def open(self, path, flags):
        # 打開文件
        full_path = self._full_path(path)
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        # 創建文件
        full_path = self._full_path(path)
        if path not in self.key:
            self.key[path]=Fernet.generate_key().decode()

        with open(self.key_path,'w') as f :
            json.dump(self.key,f)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        # 解密後讀取文件內容
        os.lseek(fh, 0, os.SEEK_SET)  # 回到文件起始位置
        if path not in self.key:
            raise FuseOSError(errno.EACCES)
        if isinstance(self.key[path],str): #轉回bytes
            self.key[path] = self.key[path].encode('utf-8')
        print("--------")
        print("read file with key =",self.key[path])
        print("--------")
        encrypted_data = os.read(fh, os.path.getsize(self._full_path(path)))
        cipher = Fernet(self.key[path])
        decrypted_data = cipher.decrypt(encrypted_data)  # 解密內容
        self.key[path] = self.key[path].decode('utf-8') #轉str
        return decrypted_data[offset:offset + length]  # 返回指定長度內容

    def write(self, path, buf, offset, fh):
        # 加密後寫入文件內容
        os.lseek(fh, 0, os.SEEK_SET)  # 回到文件起始位置
        if path not in self.key:
            raise FuseOSError(errno.EACCES)
        if isinstance(self.key[path],str):
            self.key[path] = self.key[path].encode('utf-8')
        print("---------")
        print("write file with key",self.key[path])
        print("---------")
        cipher = Fernet(self.key[path])
        encrypted_data = cipher.encrypt(buf)  # 加密內容
        os.write(fh, encrypted_data)
        self.key[path]=self.key[path].decode('utf-8')
        return len(buf)  # 返回寫入的字節數

    def truncate(self, path, length, fh=None):
        # 截斷文件
        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        # 刷新文件
        return os.fsync(fh)

    def release(self, path, fh):
        # 關閉文件
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        # 同步文件內容
        return self.flush(path, fh)

def main(mountpoint, root):
    key_path='/home/killinyeh/FUSE/key.json'
    key={}
    FUSE(EncryptedPassthrough(root,key,key_path), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
    # 獲取命令行參數，啟動文件系統
    main(sys.argv[2], sys.argv[1])
