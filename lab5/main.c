#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "crc.h"

typedef struct l2_header l2_header;
typedef struct l2_suffix l2_suffix;
typedef struct PDU PDU;
typedef struct response response;
typedef struct transmission transmission;

void print_usage(char *name);
int poll_pipe(int pipe_fd, int events);
ssize_t write_buffer(int fd, const void *buffer, size_t size);
ssize_t read_buffer(int fd, void *buffer, size_t size);

static inline uintmax_t calc_bytes(size_t n, uint8_t *bytes);
static inline void write_bytes(size_t n, uint8_t *bytes, uintmax_t value);

static inline uint32_t pdu_count_get(l2_header *header);
static inline void pdu_count_set(l2_header *header, uint32_t v);
static inline uint16_t pdu_checksum_get(l2_suffix *suffix);
static inline void pdu_checksum_set(l2_suffix *suffix, uint16_t v);

int transmit_layer1(transmission *t, PDU *pdu, size_t count, size_t seq);
int transmit_layer2(transmission *t, size_t n_packets, size_t last_size,
                    bool file_end);
int transmit_layer3(transmission *t, size_t bytes_read, bool file_end);
int transmit_layer4(transmission *t, size_t file_size);
int run_transmit(const char *fifo_path, const char *file_path);

int receive_layer1(transmission *t, int seq, PDU *pdu);
ssize_t receive_layer2(transmission *t, bool *last);
int receive_layer3(transmission *t, bool *last);
int receive_layer4(transmission *t);
int run_receive(const char *fifo_path, const char *file_path);

#define MAX_BUFFER4 2048
#define MAX_PDU 40
#define MSS 60
#define HEADER_B 40
#define TTR 16

struct l2_header {
  uint8_t stx;      // 1b = 0x02
  uint8_t count[3]; // 3b (up to 120 - b)
  uint8_t ack;      // 1b = 0
  uint8_t seq;      // 1b ++
  uint8_t lframe;   // 1b  0x01(buf)|0x0F(file)|0(regular)
  uint8_t resvd;    // 1b = 0
};

struct l2_suffix {
  uint8_t checksum[2]; // 2b CRC16-IBM
  uint8_t etx;         // 1b = 0x03
};

struct PDU {
  l2_header header;
  uint8_t l3header[HEADER_B];
  uint8_t data[MSS];
  l2_suffix suffix;
};

struct response {
  uint8_t stx; // 1b = 0x02
  uint8_t seq; // 1b ++
  uint8_t ack; // 1b = 0x06 (ok)| 0x15 (fail)
  uint8_t etx; // 1b = 0x03
};

static inline uint16_t pdu_checksum_get(l2_suffix *suffix) {
  return calc_bytes(2, suffix->checksum);
}

static inline uint32_t pdu_count_get(l2_header *header) {
  return calc_bytes(3, header->count);
}

static inline void pdu_checksum_set(l2_suffix *suffix, uint16_t v) {
  write_bytes(2, suffix->checksum, v);
}

static inline void pdu_count_set(l2_header *header, uint32_t v) {
  write_bytes(3, header->count, v);
}

void print_usage(char *name) {
  printf("Usage: %s -t [transmit] -r [receive] FIFO_PATH FILE_PATH\n", name);
}

int poll_pipe(int pipe_fd, int events) {
  struct pollfd p;
  p.fd = pipe_fd;
  p.events = events;

  int poll_res = poll(&p, 1, -1);
  if (poll_res == 1 && ((p.revents & events) == events)) {
    return 0;
  } else {
    return -1;
  }
}

static inline uintmax_t calc_bytes(size_t n, uint8_t *bytes) {
  unsigned int power = 1;
  uintmax_t result = 0;

  for (size_t i = n; i-- > 0;) {
    result += bytes[i] * power;
    power = power << 8;
  }

  return result;
}

static inline void write_bytes(size_t n, uint8_t *bytes, uintmax_t value) {
  for (size_t i = n; i-- > 0;) {
    uint8_t last_byte = value & 0xFF;
    bytes[i] = last_byte;
    value = value >> 8;
  }
}

ssize_t write_buffer(int fd, const void *_buffer, size_t size) {
  size_t bytes_counter;
  const char *buffer = _buffer;
  bytes_counter = 0;
  while (size > 0) {
    ssize_t bytes_written;
    bytes_written = write(fd, buffer, size);
    if (bytes_written < 0)
      return -1;
    buffer += bytes_written;
    size -= bytes_written;
    bytes_counter += bytes_written;
  }
  return bytes_counter;
}

ssize_t read_buffer(int fd, void *_buffer, size_t size) {
  char *buffer = _buffer;

  while (size > 0) {
    ssize_t bytes_read = read(fd, buffer, size);
    if (bytes_read < 1) {
      return -1;
    }

    buffer += bytes_read;
    size -= bytes_read;
  }

  return 0;
}

int get_pipe(const char *fifo_path, int newflags, int openflags) {
  struct stat buf;
  int pipe_fd;

  if (stat(fifo_path, &buf) < 0) {            // stat() error
    if (errno == ENOENT) {                    // fifo not found
      if (mkfifo(fifo_path, newflags) != 0) { // can't create fifo
        perror("Can't create fifo");
        return -1;
      }
    } else { // other stat error
      perror("Can't stat fifo");
      return -1;
    }
  } else {                        // stat() success
    if (!S_ISFIFO(buf.st_mode)) { // Present file is not a pipe
      fprintf(stderr, "%s is not a pipe\n", fifo_path);
      return -1;
    }
  }

  pipe_fd = open(fifo_path, openflags);
  if (pipe_fd < 0) {
    perror("Can't open pipe");
  }

  return pipe_fd;
}

struct transmission {
  PDU pdu[MAX_PDU];
  const char *fifo_path;
  int file_fd;
  uint8_t l4buff[MAX_BUFFER4];
};

int transmit_layer1(transmission *t, PDU *pdu, size_t count, size_t seq) {
  bool sent = false;

  for (size_t r = 0; r < TTR && !sent; r++) {
    int pipe_fd = get_pipe(t->fifo_path, S_IRUSR | S_IWUSR, O_WRONLY);
    ssize_t bytes_written = -1;

    if (pipe_fd < 0) {
      perror("Can't open pipe");
      continue;
    }

    if (!poll_pipe(pipe_fd, POLLOUT)) {
      bytes_written = write_buffer(pipe_fd, pdu, count);
    } else {
      fprintf(stderr, "Poll failed");
    }

    if (close(pipe_fd) < 0) {
      perror("Can't close pipe");
    }

    if (bytes_written < 0) {
      continue;
    }

    pipe_fd = get_pipe(t->fifo_path, S_IRUSR | S_IWUSR, O_RDONLY);
    if (pipe_fd < 0) {
      perror("Can't open pipe");
      continue;
    }
    response response;

    if (!poll_pipe(pipe_fd, POLLIN)) {
      if (!read_buffer(pipe_fd, &response, sizeof(response))) {
        if (response.ack == 0x06 && response.seq == seq) {
          sent = true;
          // break;
        } else {
          fprintf(stderr, "Incorrect ack or seq\n");
        }
      } else {
        fprintf(stderr, " Can't read buffer");
      }
    } else {
      perror("Poll failed");
    }

    if (close(pipe_fd) < 0) {
      perror("Can't close pipe");
    }
  }
  if (!sent) {
    return -1;
  } else {
    return 0;
  }
}

int transmit_layer2(transmission *t, size_t n_packets, size_t last_size,
                    bool file_end) {
  for (size_t i = 0; i < n_packets; i++) {
    PDU *pdu = &t->pdu[i];
    l2_header *header = &pdu->header;
    l2_suffix *suffix = &pdu->suffix;

    pdu_count_set(header, 111);
    pdu_checksum_set(suffix, 0); //default pdu_checksum_set

    header->stx = 0x02;
    header->ack = 0;
    header->seq = i;
    header->lframe = 0;
    header->resvd = 0;
    suffix->etx = 0x03;
  }

  PDU *last = &t->pdu[n_packets - 1];
  pdu_count_set(&last->header, last_size + 40 + 11);
  last->header.lframe = file_end ? 0x0F : 0x01;

  for (size_t i = 0; i < n_packets; i++) {
    PDU *pdu = &t->pdu[i];
    l2_suffix *suffix = &pdu->suffix;
    bool sent = false;
    size_t count = pdu_count_get(&pdu->header);

    if (count != MSS) { // Move suffix closer to data
      size_t data_size = 60 - (111 - count);
      suffix = (l2_suffix *)(pdu->data + data_size);
      memmove(suffix, &pdu->suffix, sizeof(l2_suffix));
    }
    write_bytes(2, suffix->checksum, calc_crc16(pdu, count));

    for (size_t r = 0; r < TTR; r++) {
      if (transmit_layer1(t, pdu, count, i) == 0) {
        sent = true;
        break;
      }
    }
    if (!sent) {
      fprintf(stderr, "Failed to send package %zu %d times\n", i, TTR);
      return -1;
    }
  }

  return 0;
}

int transmit_layer3(transmission *t, size_t bytes_read, bool file_end) {
  size_t n_packets = (bytes_read + MSS - 1) / MSS;
  if (n_packets > MAX_PDU) {
    fprintf(stderr, "Invalid buffer size\n");
    return -1;
  }

  size_t last_idx = n_packets - 1;

  size_t last_size = bytes_read % MSS; // if packet size is multiple
  if (last_size == 0) {
    last_size = MSS;
  }

  uint8_t *bytes = t->l4buff;
  for (size_t i = 0; i < n_packets - 1; i++) {
    memset(t->pdu[i].l3header, 0, HEADER_B);
    memcpy(t->pdu[i].data, bytes, MSS);
    bytes += MSS;
  }
  // handle last buffer 
  memset(t->pdu[last_idx].l3header, 0, HEADER_B);
  memcpy(t->pdu[last_idx].data, bytes, last_size);

  return transmit_layer2(t, n_packets, last_size, file_end);
}

int transmit_layer4(transmission *t, size_t file_size) {
  size_t total_read = 0;
  ssize_t bytes_read;
  do {
    bytes_read = read(t->file_fd, t->l4buff, MAX_BUFFER4); ///WRITE TO transmission
    if (bytes_read < 0) {
      perror("Can't read from input file");
      return -1;
    }

    if (bytes_read == 0) {
      fprintf(stderr, "Input file ended unexpectedly");
      return -1;
    }

    total_read += bytes_read;

    if (transmit_layer3(t, bytes_read, total_read == file_size) < 0) {
      return -1;
    }

    fprintf(stdout, "Progress: %3.2f%% %zu\n",
            (double)total_read * 100 / file_size, total_read);
  } while (total_read < file_size);

  if (total_read != file_size) {
    fprintf(stderr, "Error, file size changed\n");
    return -1;
  }

  return 0;
}

int run_transmit(const char *fifo_path, const char *file_path) {
  int file_fd;
  int exit_status;
  struct stat stat_buf;
  transmission *t;

  exit_status = EXIT_FAILURE;

  t = malloc(sizeof(transmission));

  file_fd = open(file_path, O_RDONLY);
  if (file_fd < 0) {
    perror("Can't open input file");
    goto CLOSE_TXRX;
  }

  if (fstat(file_fd, &stat_buf) < 0) {
    perror("Can't stat() input file");
    goto CLOSE_FILE;
  }

  if (stat_buf.st_size < (2 * 1024 * 1024)) { // 2 MB
    fprintf(stderr, "Can operate only on files smaller than 2 MB\n");
    goto CLOSE_FILE;
  }

  t->file_fd = file_fd;
  t->fifo_path = fifo_path;

  if (transmit_layer4(t, stat_buf.st_size) < 0) {
    fprintf(stderr, "Error during file transmission\n");
    goto CLOSE_FILE;
  }

  exit_status = EXIT_SUCCESS;

CLOSE_FILE:
  if (close(file_fd) < 0) {
    perror("Can't close input file");
  }

CLOSE_TXRX:
  free(t);

  return exit_status;
}

int receive_layer1(transmission *t, int seq, PDU *pdu) {
  response resp;
  int exit_status = -1;
  bool cs_ok = true;

  int pipe_fd = get_pipe(t->fifo_path, S_IRUSR | S_IWUSR, O_RDONLY);
  if (pipe_fd < 0) {
    perror("Can't get pipe");
    return -1;
  }

  if (poll_pipe(pipe_fd, POLLIN) < 0) {
    fprintf(stderr, "Poll failed");
    goto CLOSE_PIPE;
  }
  if (read_buffer(pipe_fd, pdu, sizeof(l2_header)) < 0) {
    fprintf(stderr, "Failed to read header from pipe\n");
    goto CLOSE_PIPE;
  }

  size_t count = pdu_count_get(&pdu->header);

  if (poll_pipe(pipe_fd, POLLIN) < 0) {
    fprintf(stderr, "Poll failed");
    goto CLOSE_PIPE;
  }

  if (read_buffer(pipe_fd, pdu->l3header, count - sizeof(l2_header)) < 0) {
    fprintf(stderr, "Failed to read data from pipe\n");
    goto CLOSE_PIPE;
  }

  size_t data_size = 60;
  l2_suffix *suffix = &pdu->suffix;
  if (count != 111) { // Move suffix far from data
    data_size = 60 - (111 - count);
    suffix = (l2_suffix *)(pdu->data + data_size);
  }

  uint16_t pcs = calc_bytes(2, suffix->checksum);
  write_bytes(2, suffix->checksum, 0);
  uint16_t ncs = calc_crc16(pdu, count);

  fflush(stdout);
  if (pcs != ncs) {
    fprintf(stderr, "Incorrect checksum\n");
    cs_ok = false;
  }

  if (suffix != &pdu->suffix) {
    memmove(&pdu->suffix, suffix, sizeof(l2_suffix));
  }

  if (pdu->header.seq != seq) {
    fprintf(stderr, "Incorrect seq\n");
    cs_ok = false;
  }

  resp.stx = 0x02;
  resp.seq = seq;
  resp.ack = 0x06;
  resp.etx = 0x03;

  if (!cs_ok) {
    resp.ack = 0x15;
  }

  if (close(pipe_fd) < 0) {
    perror("Can't close pipe");
  }

  pipe_fd = get_pipe(t->fifo_path, S_IRUSR | S_IWUSR, O_WRONLY);
  if (pipe_fd < 0) {
    perror("Can't get pipe");
    goto EXIT;
  }

  if (poll_pipe(pipe_fd, POLLOUT) < 0) {
    fprintf(stderr, "Poll failed");
    goto CLOSE_PIPE;
  }
  if (write_buffer(pipe_fd, &resp, sizeof(resp)) < 0) {
    perror("Can't write ack to pipe");
    goto CLOSE_PIPE;
  }

  exit_status = cs_ok ? 0 : -1;

CLOSE_PIPE:
  if (close(pipe_fd) < 0) {
    perror("Can't close pipe");
  }
EXIT:
  return exit_status;
}

ssize_t receive_layer2(transmission *t, bool *last) {
  bool exit_by_lframe;
  *last = false;

  exit_by_lframe = false;
  size_t n_packets = 0;
  for (size_t i = 0; i < MAX_PDU; i++) {
    PDU *pdu = &t->pdu[i];
    while (1) {
      if (receive_layer1(t, i, pdu) < 0) {
        fprintf(stderr, "Failed to read packet %zu\n", i);
      } else {
        break;
      }
    }

    n_packets++;

    if (pdu->header.lframe == 0x0F) {
      *last = true;
    }
    if (pdu->header.lframe != 0) {
      exit_by_lframe = true;
      break;
    }
  }

  return exit_by_lframe ? (ssize_t)n_packets : -1;
}

int receive_layer3(transmission *t, bool *last) {
  *last = false;
  size_t bytes_read = 0;

  int packets_read_ = receive_layer2(t, last);
  if (packets_read_ < 0) {
    return -1;
  }
  size_t packets_read = (size_t)packets_read_;

  size_t buff_pred = 0;
  for (size_t i = 0; i < packets_read; i++) {
    buff_pred += MSS - (sizeof(PDU) - pdu_count_get(&t->pdu[i].header));
  }
  if (buff_pred > MAX_BUFFER4) {
    for (size_t i = 0; i < packets_read - 1; i++) {
      if (t->pdu[i].header.lframe != 0) {
        puts("ERRROR!!!");
      }
    }
    printf("Buff size: %zu\n", buff_pred);
    fprintf(stderr, "Too big buffer was read\n");
    return -1;
  }

  uint8_t *buffer = t->l4buff;
  for (size_t i = 0; i < packets_read; i++) {
    size_t pkt_size = pdu_count_get(&t->pdu[i].header);
    size_t data_size = MSS - (sizeof(PDU) - pkt_size);

    memcpy(buffer, t->pdu[i].data, data_size);
    buffer += data_size;
    bytes_read += data_size;
  }

  return bytes_read;
}

int receive_layer4(transmission *t) {
  int result = -1;
  size_t total_read = 0;

  while (1) {
    bool last;
    int bytes_read = receive_layer3(t, &last);
    if (bytes_read < 0) {
      fprintf(stderr, "Can't receive next buffer\n");
      break;
    }
    total_read += bytes_read;

    printf("Read: %zu Buffer: %d\n", total_read, bytes_read);
    if (write_buffer(t->file_fd, t->l4buff, bytes_read) < 0) {
      fprintf(stderr, "Can't write to output file\n");
      break;
    }

    if (last) {
      result = 0;
      break;
    }
  }

  return result;
}

int run_receive(const char *fifo_path, const char *file_path) {
  int file_fd;
  int exit_status;
  transmission *t;

  exit_status = EXIT_FAILURE;

  t = malloc(sizeof(transmission));

  file_fd = creat(file_path, 0644);
  if (file_fd < 0) {
    perror("Can't open output file");
    goto CLOSE_TXRX;
  }

  t->file_fd = file_fd;
  t->fifo_path = fifo_path;

  if (receive_layer4(t) < 0) {
    fprintf(stderr, "Error during file receive\n");
    goto CLOSE_FILE;
  }

  exit_status = EXIT_SUCCESS;

CLOSE_FILE:
  if (close(file_fd) < 0) {
    perror("Can't close output file");
  }

CLOSE_TXRX:
  free(t);

  return exit_status;
}

int main(int argc, char *argv[]) {
  const char *fifo_path, *file_path;
  int exit_status;
  bool transmit;

  assert(sizeof(PDU) == 111);
  assert(sizeof(l2_header) == 8);
  assert(sizeof(l2_suffix) == 3);
  assert(sizeof(response) == 4);

  crcInit();

  signal(SIGPIPE, SIG_IGN); //IGNORE SIGPIPE

  exit_status = EXIT_FAILURE;

  if (argc != 4) {
    print_usage(argv[0]);
    goto EXIT;
  }

  if (strcmp(argv[1], "-t") == 0) {
    transmit = true;
  } else if (strcmp(argv[1], "-r") == 0) {
    transmit = false;
  } else {
    print_usage(argv[0]);
    goto EXIT;
  }

  fifo_path = argv[2];
  file_path = argv[3];

  if (transmit) {
    exit_status = run_transmit(fifo_path, file_path);
  } else {
    exit_status = run_receive(fifo_path, file_path);
  }

EXIT:
  exit(exit_status);
}
