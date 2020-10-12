#ifndef BT_FSM_H
#define BT_FSM_H

#include "stddef.h"
#include "stdint.h"

/** Konstanta untuk FSM **/
#define BT_BUF_LEN_BYTE 32
#define BT_BUF_LEN_BIT 256
#define BT_BLOCK_SIZE_BYTE 16
#define BT_BLOCK_SIZE_BIT 128
#define BT_SUCCESS 0
#define BT_FAIL -1
#define BT_ENABLE 1
#define BT_DISABLE 0
#define BT_ADDR_LEN 6
#define BT_RSA_PK_KEYLEN 449
#define BT_NUM_STATES 13
#define BT_ALARM_DURATION_SEC 5
#define BT_REPLY_TIMEOUT_SEC 60

/** 
 * @brief Pesan balasan dari Immobilizer, menandakan status Immobilizer ke HP
 * 
 * Enumerasi berisi kode status Immobilizer, untuk sinkronisasi State Machine
 * antara HP dan Immobilizer
 */
typedef enum BTReply
{
    NACK = '0',   /**< Not Acknowledged, data dari HP tidak sesuai dengan yang diinginkan **/
    ACK = '1',    /**< Acknowledged, data dari HP sesuai yang diinginkan **/
    ERR = '2',    /**< Terjadi error pada Immobilizer **/
    ACK_UNL = '3' /**< Acknowledge, data dari HP sesuai yang diinginkan, dan Immobilizer dalam keadaan unlocked **/
} bt_reply;

/**
 * @brief Kode request yang dapat diterima Immobilizer
 * 
 * Enumerasi berisi kode request yang dapat diterima Immobilizer, disimpan dalam
 * tipe data uint8_t (char)
 */
typedef enum BTRequest
{
    REQUEST_NOTHING = '0',  /**< 0: Tidak ada request, hanya untuk kenyamanan dan debugging **/
    REQUEST_UNLOCK,         /**< 1: Request unlock immobilizer. Berfungsi ganda untuk mengunci immobilizer 
                                   jika immobilizer sudah dalam keadaan terbuka/unlock **/
    REQUEST_CHANGE_PIN,     /**< 2: Request ubah pin immobilizer **/
    REQUEST_REGISTER_PHONE, /**< 3: Request daftar HP ke Immobilizer **/
    REQUEST_REMOVE_PHONE,   /**< 4: Request hapus akun dari Immobilizer **/
    REQUEST_DISABLE         /**< 5: Request disable immobilizer. Tidak/belum diimplementasi **/
} bt_request;

/** 
 * @brief Tipe event yang ada pada FSM
 * 
 * Enumerasi berisi konstanta yang berfungsi sebagai pembeda event apa yang diterima
 * FSM pada Immobilizer
 */
typedef enum BTEvent
{
    EVENT_TRANSITION,    /**< Event transisi antara satu state ke state lain **/
    EVENT_BT_INPUT,      /**< Event terdapat input ke Bluetooth Immobilizer **/
    EVENT_BT_INPUT_END,  /**< Event input bluetooth selesai **/
    EVENT_BT_OUTPUT,     /**< Event terdapat output dari Bluetooth Immobilizer **/
    EVENT_BT_CONNECT,    /**< Event terdapat sambungan baru ke Bluetooth Immobilizer **/
    EVENT_BT_DISCONNECT, /**< Event sambungan terputus pada Bluetooth Immobilizer **/
    EVENT_TIMEOUT,       /**< Event batas waktu habis, atau terjadi hang **/
    EVENT_ERROR,         /**< Event terjadi error pada Immobilizer **/
    EVENT_ALARM_OFF,     /**< Event alarm mati **/
    EVENT_ENGINE,        /**< Event keadaan mesin berubah **/
    EVENT_S_INPUT,       /**< Event terdapat input serial dari PC dsb. , untuk debugging **/
    EVENT_SET_CREDENTIAL /**< Event gak tau, tidak diimplementasi **/
} bt_event;

/**
 * @brief Tipe data untuk input FSM Immobilizer
 * 
 * Tipe data untuk input FSM Immobilizer, berisi array dan flag tipe event yang terjadi
 */
typedef struct BTBuffer
{
    uint8_t data[BT_BUF_LEN_BYTE]; /**< Array berukuran BT_BUF_LEN_BYTE, menyimpan data **/
    size_t len;                    /**< Ukuran data **/
    bt_event event;                /**< Tipe event yang terjadi **/
} bt_buffer;

/**
 * @brief Deklarasi enum state pada FSM 
 * 
 * Diminta dari compiler, untuk correctness
 */
typedef enum FSMState
{
    STATE_ERR = 0,
    STATE_DISCONNECT,
    STATE_CONNECT,
    STATE_CHALLENGE,
    STATE_VERIFICATION,
    STATE_PIN,
    STATE_UNLOCK,
    STATE_NEW_PIN,
    STATE_DELETE,
    STATE_ALARM,
    STATE_KEY_EXCHANGE,
    STATE_REGISTER,
    STATE_UNLOCK_DISCONNECT
} fsm_state;

/**
 * @brief Menginisialisasi struct bt_buffer
 * 
 * @param buffer Pointer ke bt_buffer yang akan diinisialisasi
 */
void init_bt_buffer(bt_buffer *buffer);

/** 
 * @brief Interface antara FSM dengan modul lain pada ESP32
 * 
 * Interface antara FSM dengan modul lain pada ESP32. Berisi pointer
 * ke fungsi yang mengimplementasi fungsionalitas yang diinginkan
 */
typedef struct FSMInterface
{
    /** <
     * @brief Mem-print state FSM, untuk debugging
     * @param fsm_state State FSM terbaru
     */
    void (*announceStateImp)(fsm_state);

    /** <
     * @brief Menghasilkan nonce/array dengan nilai acak
     * @param nonce bt_buffer yang menyimpan nonce yang dihasilkan
     * @return BT_SUCCESS jika berhasil, BT_FAIL jika gagal
     * @note Panjang nonce yang dihasilkan selalu 16 byte (BT_BLOCK_SIZE_BYTE)
     */
    int (*generateNonceImp)(bt_buffer *);

    /** < 
     * @brief Mengirim bt_reply ke client
     * @param reply Balasan yang diinginkan
     * @return BT_SUCCESS jika berhasil, BT_FAIL jika gagal
     */
    int (*sendReplyImp)(bt_reply);

    /** <
     * @brief Mengirim bt_buffer ke client
     * @param outbuf buffer yang menyimpan output ke client
     * @return BT_SUCCESS jika berhasil, BT_FAIL jika gagal
     */
    int (*writeBTImp)(const bt_buffer *);

    /** <
     * @brief Melakukan dekripsi pada sebuah bt_buffer
     * @param ciphertext bt_buffer berisi data terenkripsi
     * @param msg bt_buffer yang menyimpan hasil dekripsi
     * @return BT_SUCCESS jika berhasil, BT_FAIL jika gagal
     * @note Perhatikan padding
     */
    int (*decryptBTImp)(const bt_buffer *, bt_buffer *);

    /** <
     * @brief Menyimpan user credential ke memori
     * @param pin bt_buffer yang menyimpan data PIN pengguna
     * @param client bt_buffer yang menyimpan data MAC address pengguna
     * @return BT_SUCCESS jika berhasil, BT_FAIL jika gagal
     */    
    int (*storeCredentialImp)(bt_buffer *, bt_buffer *);

    /** <
     * @brief Menghapus user credential dari memori
     * @return BT_SUCCESS jika berhasil
     */
    int (*deleteStoredCredentialImp)(void);

    /** <
     * @brief Mengeset public key berdasarkan kunci RSA
     * @return BT_SUCCESS jika berhasil
     * @param keybuf Array yang menyimpan Public Key
     * @param keylen Panjang public key
     */
    int (*loadPKImp)(uint8_t *, size_t);

    /** <
     * @brief Mengeset kunci simetris AES
     * @param cipherkey bt_buffer yang menyimpan kunci AES
     * @return BT_SUCCESS jika berhasil
     */
    int (*setCipherkeyImp)(const bt_buffer *);

    /** <
     * @brief Mengirim data terenktripsi RSA melalui bluetooth ke client
     * @param outbuf bt_buffer yang menyimpan data output
     * @return BT_SUCCESS jika berhasil
     */
    int (*writeBTRSAImp)(const bt_buffer *);

    /** <
     * @brief Menyalakan atau mematikan alarm
     * @param enable BT_ENABLE untuk menyalakan, BT_DISABLE untuk mematikan
     * @param duration Waktu alarm menyala dalam detik
     */
    int (*setAlarmImp)(int, int);

    /** <
     * @brief Menyalakan atau mematikan timer timeout
     * @param enable BT_ENABLE untuk menyalakan, BT_DISABLE untuk mematikan
     * @param duration Batas waktu untuk timer, dalam detik
     */
    int (*setTimeoutImp)(int, int);

    /** <
     * @brief Melakukan unpairing pada client
     * @param client bt_buffer yang menyimpan MAC address client
     * @return BT_SUCCESS jika berhasil
     */
    int (*unpairBlacklistImp)(const bt_buffer *);

    /** <
     * @brief Menyalakan atau mematikan Immobilizer
     * @param enable BT_ENABLE untuk menyalakan, BT_DISABLE untuk mematikan
     */
    void (*setImmobilizerImp)(int);

    /** <
     * @brief Meng-handle error
     */
    void (*handleErrorImp)(void);

    /** <
     * @brief Memutuskan koneksi ke client
     */
    void (*disconnectImp)(void);

    /** <
     * @brief Mengatur discoverability perangkat
     * @param enable BT_ENABLE agar discoverability on, BT_DISABLE off
     * @return BT_SUCCESS jika berhasil
     */
    int (*setDiscoverabilityImp)(int);
} fsm_interface;

/**
 * @brief Menginisialisasi FSM Immobilizer
 * 
 * Menginisialisasi FSM Immobilizer. Parameter yang dimasukkan adalah pointer ke fungsi
 * yang mengimplementasi interaksi FSM dengan modul-modul lain seperti enkripsi, dekripsi,
 * penyimpanan file, bluetooth, dan sebagainya.
 * 
 * @return BT_SUCCESS jika berhasil, BT_FAIL jika gagal
 * @param interface Implementasi fungsi interfacing FSM
 * @see fsm_interface
 */
int init_btFsm(const fsm_interface *interface);

/** 
 * @brief Mengecek apakah 2 bt_buffer menyimpan data yang sama
 * 
 * @return BT_SUCCESS jika sama, BT_FAIL jika tidak
 */
int compareBT(const bt_buffer *buf1, const bt_buffer *buf2);

/**
 * @brief Parse user request dari sebuah bt_buffer
 * 
 * @return Request yang terparse. Jika tidak sesuai format, me-return REQUEST_NOTHING
 */
bt_request parse_request(const bt_buffer *buffer);

/** ---------------------------------------------------------- **/
/** FUNGSI YANG MEMANGGIL FSM                                  **/
/** FSM yang dibuat asinkron dan event-based                   **/
/** ---------------------------------------------------------- **/

/** 
 * @brief Memanggil FSM dengan event input bluetooth
 * 
 * @param data Array yang menyimpan data terbaru yang masuk
 * @param len Panjang data terbaru yang masuk
 */
void onBTInput(const uint8_t *data, size_t len);

/** 
 * @brief Memanggil FSM dengan event input bluetooth berakhir
 * 
 * @note Digunakan pada saat key exchange dilakukan, atau input dari bluetooth lebih besar dari ukuran buffer
 */
void onBTInputEnd();

/** 
 * @brief Memanggil FSM dengan event input dari serial
 * 
 * @param data Array yang menyimpan data terbaru yang masuk
 * @param len Banyak data terbaru yang masuk
 */
void onSInput(const uint8_t *data, size_t len);

/** 
 * @brief Memanggil FSM dengan event keadaan mesin berubah
 * 
 * @param data BT_ENABLE jika mesin menyala, BT_DISABLE jika tidak
 * @note Saat ini tidak ada bedanya antara BT_ENABLE atau BT_DISABLE hehe
 */
void onEngineEvent(int data);

/** 
 * @brief Memanggil FSM dengan event batasan waktu habis
 */
void onTimeout();

/** 
 * @brief Memanggil FSM dengan event sambungan bluetooth terbaru
 * 
 * @param addr Alamat client
 * @param len Panjang alamat client, seharusnya 6
 */
void onBTConnect(const uint8_t *addr, size_t len);

/** 
 * @brief Memanggil FSM dengan event sambungan bluetooth terputus
 * 
 * @param addr Alamat client
 * @param len Panjang alamat client, seharusnya 6
 */
void onBTDisconnect(const uint8_t *addr, size_t len);

/**
 * @brief Memanggil FSM dengan event transisi ke state baru
 * 
 * @note Berfungsi ganda untuk me-reset state
 * @note Jangan panggil dari luar, kecuali kalau terpaksa banget
 */
void onTransition();

/**
 * @brief Menyimpan user credential (PIN, dan address client) pada FSM
 * 
 * @return BT_SUCCESS jika berhasil, BT_FAIL jika gagal karena tidak sesuai format
 * 
 * @param pin Array yang menyimpan PIN pengguna
 * @param plen Panjang PIN pengguna
 * @note Panjang PIN tidak boleh melebihi BT_BLOCK_SIZE_BYTE (16 karakter)
 * @param addr Address client (HP pengguna)
 * @param alen Panjang address client (HP pengguna)
 * @note Panjang address seharusnya adalah 6 karakter
 */
int load_user_cred(const uint8_t *pin, size_t plen, const uint8_t *addr, size_t alen);

/**
 * @brief Menyimpan user credential (PIN, dan address client) pada FSM
 * 
 * @return BT_SUCCESS jika berhasil, BT_FAIL jika gagal karena tidak sesuai format
 * 
 * @param pin Array yang menyimpan PIN pengguna
 * @param plen Panjang PIN pengguna
 * @note Panjang PIN tidak boleh melebihi BT_BLOCK_SIZE_BYTE (16 karakter)
 */
int set_user_pin(const uint8_t *pin, size_t plen);

/** 
 * @brief Mendapatkan state terbaru pada FSM
 * 
 * @return State terbaru FSM
 */
fsm_state get_current_state();

/**
 * @brief Mendapatkan status registrasi (apakah ada HP terdaftar) pada FSM
 * 
 * @return Status registrasi terakhir
 */
unsigned int get_registration_status();

#endif // !BT_FSM_H