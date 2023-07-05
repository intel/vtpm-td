#include <stddef.h>
#include <stdint.h>

typedef void RAND_POOL;

int rand_pool_add(RAND_POOL *pool,
                  const unsigned char *buffer, size_t len, size_t entropy);
unsigned char *rand_pool_add_begin(RAND_POOL *pool, size_t len);
int rand_pool_add_end(RAND_POOL *pool, size_t len, size_t entropy);
size_t rand_pool_bytes_needed(RAND_POOL *pool, unsigned int entropy_factor);
size_t rand_pool_entropy_available(RAND_POOL *pool);

extern uint32_t __fw_rdrand32(void);

static uint32_t
rand32(
    void)
{
  return __fw_rdrand32();
}

static size_t rand_get_bytes(size_t amount, unsigned char *entropy)
{
  uint32_t left, multi4_total;
  uint32_t tmp_value;
  if (amount == 0)
  {
    return 0;
  }
  left = amount % 4;
  multi4_total = amount - left;
  if (multi4_total != 0)
  {
    for (uint32_t index = 0; index < multi4_total; index += 4)
    {
      *(uint32_t *)(entropy + index) = rand32();
    }
  }
  if (left != 0)
  {
    tmp_value = rand32();
    for (uint32_t index = 0; index < left; index++)
    {
      *(entropy + multi4_total + index) = *((unsigned char *)&tmp_value + index);
    }
  }

  return amount;
}

/*
 * Add random bytes to the pool to acquire requested amount of entropy
 *
 * This function is platform specific and tries to acquire the requested
 * amount of entropy by polling platform specific entropy sources.
 *
 * This is OpenSSL required interface.
 */
size_t
rand_pool_acquire_entropy(
    RAND_POOL *pool)
{
  size_t Bytes_needed;
  unsigned char *Buffer;
  size_t ret_bytes;

  Bytes_needed = rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
  if (Bytes_needed > 0)
  {
    Buffer = rand_pool_add_begin(pool, Bytes_needed);

    if (Buffer != NULL)
    {
      ret_bytes = rand_get_bytes(Bytes_needed, Buffer);
      if (ret_bytes < Bytes_needed)
      {
        rand_pool_add_end(pool, 0, 0);
      }
      else
      {
        rand_pool_add_end(pool, Bytes_needed, 8 * Bytes_needed);
      }
    }
  }

  return rand_pool_entropy_available(pool);
}

/*
 * Implementation for UEFI
 *
 * This is OpenSSL required interface.
 */
int rand_pool_add_nonce_data(
    RAND_POOL *pool)
{
  uint8_t data[16];
  rand_get_bytes(sizeof(data), data);

  return rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0);
}

/*
 * Implementation for UEFI
 *
 * This is OpenSSL required interface.
 */
int rand_pool_add_additional_data(
    RAND_POOL *pool)
{
  uint8_t data[16];
  rand_get_bytes(sizeof(data), data);

  return rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0);
}

/*
 * Dummy Implementation for UEFI
 *
 * This is OpenSSL required interface.
 */
int rand_pool_init(
    void)
{
  return 1;
}

/*
 * Dummy Implementation for UEFI
 *
 * This is OpenSSL required interface.
 */
void rand_pool_cleanup(
    void)
{
}

/*
 * Dummy Implementation for UEFI
 *
 * This is OpenSSL required interface.
 */
void rand_pool_keep_random_devices_open(
    int keep)
{
}
