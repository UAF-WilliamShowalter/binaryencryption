section .text
global hashingAlgorithm
hashingAlgorithm:

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; This is a 32bit program to perform hashing on an array of data
; Data array must be of a length 1 32bit block or more.
;
; If size == 0, returns pointer passed in (begin == end)
; If size == 1, returns data from 32bit block - no hashing performed
;
;
; Hash used is simple xor hash. All data blocks are xor'd against each other.'
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;   Variable table
;   eax = hashed block
;   ecx = data pointer
;   edi = data end pointer
;   esi = dereferenced data
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


; Pointer math -> +4 for return address == base of +4 for passed data

mov eax,[esp+4]         ; move ptr to first block into hashing block

mov ecx,eax             ; move second block ptr into data ptr block
add ecx,4               ;

mov edi,[esp+8]         ; move end ptr into register

cmp eax,edi             ; check if size == 0
je hashing_done

mov eax,[eax]           ; move first block into hashing block

hashing_loop:

cmp ecx,edi             ; check for end condition
je hashing_done

mov esi,[ecx]           ; loads data from data ptr location
xor eax,esi             ; hashes block

add ecx,4               ; increment data
jmp hashing_loop

hashing_done:
ret                     ; returns hash

