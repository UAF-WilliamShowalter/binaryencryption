section .text
global encryptionAlgorithm
encryptionAlgorithm:

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; This is a 32bit program to perform a chain xor encryption on an array of data
; The program takes 4 pointers, to first and last+1 elements of a data array and a key array, and an integer value 0/1 whether to encrypt or decrypt, respectively.
;
; The encryption protocol is as follows:
;   1.  xor array with key, if key is shorter than array, loop back to beginning of key when last element is used.
;   2.  Perform a right circular bit rotate (ror) of 1 bit on each 32bit element of array.
;   3.  Repeat steps 1 and 2 until the a certain number of encryptions and shifts have occurred.
;       Right now this is hardcoded at 16, doesn't really matter how many times you set it to, but you start looping back after 32.
;       The client code needs to account for the fact that these rotates have happened when storing the last block of the encrypted data,
;           either by removing the unmeaningful bits, or by tracking the length and storing the message/last block.
;
; Decryption protocol mirrors the encryption, but it left circular rotates (rol) first, then xor's, in order to undo the encryption operation.
;
; **NOTE**
;   I am not a crytologist/cryptanalyst and have not analysed this encryption algorithm for security.
;       Some implementation choices may very well lower security.
;
; ** DO NOT expect actual security if you choose to encrypt actual data using this.
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

push ebx    ; preserved - and we need all the registers we can get
push ebp    ; preserved

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;   Variable table
;   eax = rotate counter
;   ecx = data pointer
;   edx = key pointer
;   esi = dereferenced data
;   ebp = key data
;   ebx = scratch, used for moving from stack to memory
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

mov eax, -1              ; our bit rotate counter, after every xor, rotate right by one bit, then increment and xor

mov ebx, [esp+28]        ; whether we do encryption or decryption
mov dword [encryptDecrypt], ebx;
mov ebx, 0

mov ebx, DWORD [esp+16]  ; Grab data end pointer
mov dword [dataEnd], ebx ; store data end pointer
mov ebx, 0               ; current position, starts at 0

; Encrypt xor's first, decrypt rotates first.
cmp DWORD [encryptDecrypt],0
je next_xor_round
jmp _bitrotate

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;   Beginning of XOR function, restarts after every bit rotate
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

next_xor_round:
cmp DWORD [encryptDecrypt], 1
je next_xor_round_dec

;; increment here if encrypting
add eax,1                ; increment rotate count, started at -1, so first time edx = 0
cmp eax, [rotateCount]   ; are we done with the last bit rotate

;;;;;;;;;;;;;;;;;;;;;;;;;;
je donejump1             ; exit condition
;;;;;;;;;;;;;;;;;;;;;;;;;;

next_xor_round_dec:

; Pointer math -> +4 for return address, +4 for pushed ebp, +4 for pushed edx == base of +12 for passed data
mov ecx, DWORD [esp+12]  ; Grab pointer to data

mov edx, DWORD [esp+20]  ; Grab pointer to key

mov ebx, DWORD [esp+24]  ; grab  key end pointer
mov DWORD [keyEnd], ebx     ; store key end pointer
mov ebx,0


; Beginning of XOR loop, iterating through array elements

restart_key:
mov edx, DWORD [esp+20]            ; sets key pointer back to position 0

xor_next_int:
cmp ecx, [dataEnd]
je _bitrotate



mov esi, DWORD [ecx]    ; Dereference pointer
mov ebp, DWORD [edx]    ; Dereference key


xor DWORD esi, DWORD ebp ; xor encryption of data and key
mov DWORD [ecx], esi     ; store back to memory


add ecx,4;              ; increments data position
add edx,4;              ; increments key position

cmp edx,[keyEnd]        ; checks key position
je restart_key

jmp xor_next_int



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
donejump1:      ; Was getting an error about short jump distance, two jumps worked though...
jmp done
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Bitwise rotate function
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

_bitrotate:
cmp DWORD [encryptDecrypt], 0
je _bitrotate_enc
;; increment here if decrypting
add eax,1                ; increment rotate count, started at -1, so first time edx = 0
cmp eax, [rotateCount]   ; are we done with the last bit rotate
je donejump1             ; exit condition

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;   Variable table
;
;   eax = rotate counter
;   ecx = data pointer
;   esi = dereferenced data
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;3;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

_bitrotate_enc:          ; encryption jump point
; Pointer math -> +4 for return address, +4 for pushed ebx, +4 for pushed ebp == base of +12 for passed data

mov ecx, DWORD [esp+12]  ; Grab pointer to data

rotate_next_int:
cmp ecx, [dataEnd]      ; if we have reached end of this loop, go back to top
je next_xor_round

mov esi, DWORD [ecx]    ; Dereference pointer

; Encryption Rotates

cmp DWORD [encryptDecrypt],1
je left_rotate
ror DWORD esi, 1        ; right rotate of data
left_rotate:

; Decryption rotates

cmp DWORD [encryptDecrypt],0
je after_enc_landing
rol DWORD esi, 1        ; left rotate of data

after_enc_landing:


mov DWORD [ecx], esi    ; store back to memory


add ecx,4               ; increments data position

jmp rotate_next_int


done:
pop ebp                 ; restore preserved registers
pop ebx                 ; restore preserved registers
ret


section .data
keyEnd:
    dd 0x0              ; key.end (last+4 bytes)
dataEnd:
    dd 0x0              ; data.end (last+4 bytes)
rotateCount:
    dd 0x10             ; how many bit rotates to do ** THIS MUST MATCH UP WITH THE CONSTANT IN THE SAVE FUNCTION FOR THE OUTPUT FILE IN THE LINKED C++
encryptDecrypt:
    dd 0x0              ; 0 == encrypt, 1 == decrypt












