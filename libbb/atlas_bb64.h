
struct buf
{
        size_t offset;
        size_t size;
        size_t maxsize;
        char *buf;
        int fd;
};

void buf_init(struct buf *buf, int fd);
int buf_add(struct buf *buf, const void *data, size_t len );
int buf_add_b64(struct buf *buf, void *data, size_t len, int mime_nl);
void buf_cleanup(struct buf *buf);
