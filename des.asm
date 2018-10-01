;Maxim Gelfand
;-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
;-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
;																								DDDDDDDDDDDDD      EEEEEEEEEEEEEEEEEEEEEE   SSSSSSSSSSSSSSS 
;																								D::::::::::::DDD   E::::::::::::::::::::E SS:::::::::::::::S
;																								D:::::::::::::::DD E::::::::::::::::::::ES:::::SSSSSS::::::S
;																								DDD:::::DDDDD:::::DEE::::::EEEEEEEEE::::ES:::::S     SSSSSSS
;																								  D:::::D    D:::::D E:::::E       EEEEEES:::::S            
;																								  D:::::D     D:::::DE:::::E             S:::::S            
;																								  D:::::D     D:::::DE::::::EEEEEEEEEE    S::::SSSS         
;																								  D:::::D     D:::::DE:::::::::::::::E     SS::::::SSSSS    
;																								  D:::::D     D:::::DE:::::::::::::::E       SSS::::::::SS  
;																								  D:::::D     D:::::DE::::::EEEEEEEEEE          SSSSSS::::S 
;																								  D:::::D     D:::::DE:::::E                         S:::::S
;																								  D:::::D    D:::::D E:::::E       EEEEEE            S:::::S
;																								DDD:::::DDDDD:::::DEE::::::EEEEEEEE:::::ESSSSSSS     S:::::S
;																								D:::::::::::::::DD E::::::::::::::::::::ES::::::SSSSSS:::::S
;																								D::::::::::::DDD   E::::::::::::::::::::ES:::::::::::::::SS 
;																								DDDDDDDDDDDDD      EEEEEEEEEEEEEEEEEEEEEE SSSSSSSSSSSSSSS   
;-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
;-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
p286
IDEAL
MODEL small
STACK 100h
DATASEG
;																									 __      __        _       _     _               
;																									 \ \    / /       (_)     | |   | |            _ 
;																									  \ \  / /_ _ _ __ _  __ _| |__ | | ___  ___  (_)
;																									   \ \/ / _` | '__| |/ _` | '_ \| |/ _ \/ __|    
;																										\  / (_| | |  | | (_| | |_) | |  __/\__ \  _ 
;																										 \/ \__,_|_|  |_|\__,_|_.__/|_|\___||___/ (_)
	;------------- Mode variables -------------
	enc db 0 ;boolean - encryption mode
	block db 8 dup (0)
	doneBl db 8 dup (?)
	iv db 8 dup (0h)
	cbc_temp db 16 dup (0)
	nonce db 6 dup (0)
	ctr_temp db 8 dup (0)
	;------------------------------------------
	;------------- Console messages/variables -------------
	WlcMsg db 0Ah, '	     Welcome to the DES program made by Maxim Gelfand!',  0Ah, 'This program encrypts or decrypts a txt file according to the DES algorithm, ', 0Ah, 'according to the ECB, CBC and CTR modes of operation and with padding according to PKCS#7. To get started, create a txt file in the directory from which you arerunning this program, name it des.txt and put', 0Ah
		   db 'your plaintext or ciphertext there.', 0Ah, 'Press any key when your file is ready.', 0Ah, '$'
	ch1Msg db 0Ah, 'For encryption press e,', 0Ah, 'for decryption press d:', 0Ah, '$'
	modMsg db 0Ah, 'Please choose an operation mode: ', 0Ah, 'Press 1 for ECB (Electronic Code Book), ', 0Ah, 'Press 2 for CBC (Cipher Block Chaining), ', 0Ah, 'Press 3 for CTR (CounTeR, note that the size of the txt file must contain 524280characters at most). ', 0Ah, '$'
	keyMsg db 0Ah, 'Please enter your secret key: 8 bytes = 16 hexadecimal digits, lowercase. ', 0Ah, 'e.g. 0123456789abcdef :', 0Ah, '$'
	ivMsg db 0Ah, 'Please enter the initialization vector for the cipher block chaining: 8 bytes = 16 hexadecimal digits, lowercase. e.g. 0123456789abcdef : ', 0Ah, '$'
	nncMsg db 0Ah, 'Please enter the nonce: 6 bytes = 12 hexadecimal digits, lowercase. ', 0Ah, 'e.g. 0123456789ab : ', 0Ah, '$'
	wrkMsg db 0Ah, 'Working on it... This may take a while, depending on the length of the file.', 0Ah, '$'
	dneMsg db 0Ah, 'Done! Check your file.', 0Ah, '$'
	;------------------------------------------------------
	;------------- Files variables -------------
	filename db 'des.txt', 0
	filehandle dw ?
	ErrorMsg db 0Ah, 'Error, file not found. Please create a file with your ciphertext or plaintext, name it des.txt and put it in your TASM/bin directory. Press any key when your ', 0Ah, 'file is ready.', 10, 13,'$'
	;-------------------------------------------
	;------------- Padding variables -------------
	lastBl db 0 ;boolean - operating on last block
	done db 0 ;boolean - turns on if the block is after the last one and should not be encrypted.
	p_num dw 0
	p_add dw ?
	;---------------------------------------------
	;------------- Key Schedule variables -------------
	key db 8 dup (0h)
	k_temp db 7 dup (?)
	k_temp2 db 7 dup (?)
			db 2 dup (0FFh)
			db '1:'
	subKey01 db 6 dup (?)
			db '2:'
	subKey02 db 6 dup (?)
			db '3:'
	subKey03 db 6 dup (?)
			db '4:'
	subKey04 db 6 dup (?)
			db '5:'
	subKey05 db 6 dup (?)
			db '6:'
	subKey06 db 6 dup (?)
			db '7:'
	subKey07 db 6 dup (?)
			db '8:'
	subKey08 db 6 dup (?)
			db '9:'
	subKey09 db 6 dup (?)
			db 'A:'
	subKey10 db 6 dup (?)
			db 'B:'
	subKey11 db 6 dup (?)
			db 'C:'
	subKey12 db 6 dup (?)
			db 'D:'
	subKey13 db 6 dup (?)
			db 'E:'
	subKey14 db 6 dup (?)
			db 'F:'
	subKey15 db 6 dup (?)
			db 'G:'
	subKey16 db 6 dup (?)
	rotMap db 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
	crntKN db ?
	;--------------------------------------------------
	;------------- get/write variables -------------
	gw_bit db ?
	g_address dw ?
	w_address dw ?
	gw_bits dw ?
	map1 db 00000001b, 00000010b, 00000100b, 00001000b, 00010000b, 00100000b, 01000000b, 10000000b
	map2 db 11111110b, 11111101b, 11111011b, 11110111b, 11101111b, 11011111b, 10111111b, 01111111b
	;-----------------------------------------------
	;------------- Permutation Tables -------------
	IP db 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
	IP1 db 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
	E db 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
	P db 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
	PC1 db 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
	PC2 db 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
	leftRot db 28, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 56, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55
	;we will decrease what we read from the tables.
	;----------------------------------------------
	;------------- f function variables -------------
	e_temp db 6 dup (?)
	s_temp2 db 4 dup (?)
	f_temp db 4 dup (?)
	;--------------------------------------------
	;------------- Substitution boxes ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	s1 db 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 ;|
	s2 db 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 ;|
	s3 db 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 ;|
	s4 db 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 ;|
	s5 db 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ;|
	s6 db 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 ;|
	s7 db 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 ;|
	s8 db 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 ;|
	;------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	;------------- SBox algorithm variables -------------
	s_temp db ?
	s_line db ?
	s_col db ?
	s_idx dw ?
	;----------------------------------------------------
	;------------- Feistel network variables -------------
	n_var db 8 dup (?)
	n_temp db 8 dup (?)
	n_round db 0
	;-----------------------------------------------------
	return_address dw ?
	trash dw ?
CODESEG
;																	  _____                        _                                       _   __  __                              
;																	 |  __ \                      | |                                     | | |  \/  |                           _ 
;																	 | |__) | __ ___   ___ ___  __| |_   _ _ __ ___  ___    __ _ _ __   __| | | \  / | __ _  ___ _ __ ___  ___  (_)
;																	 |  ___/ '__/ _ \ / __/ _ \/ _` | | | | '__/ _ \/ __|  / _` | '_ \ / _` | | |\/| |/ _` |/ __| '__/ _ \/ __|    
;																	 | |   | | | (_) | (_|  __/ (_| | |_| | | |  __/\__ \ | (_| | | | | (_| | | |  | | (_| | (__| | | (_) \__ \  _ 
;																	 |_|   |_|  \___/ \___\___|\__,_|\__,_|_|  \___||___/  \__,_|_| |_|\__,_| |_|  |_|\__,_|\___|_|  \___/|___/ (_)
;------------------------------------------------------------------------------------------------
;											PADDING PROC
;------------------------------------------------------------------------------------------------
PROC pad
	call doneBlP
	cmp ax, 4
	jne p_cont
	mov [done], 1
	ret
	p_cont:
		mov si, 1
		padLoop:
			mov bx, [p_add]
			cmp [byte ptr bx + si], 0
			je padding
			inc si
			cmp si, 8
			jl padLoop
		ret
		padding:
			mov [lastBl], 1
			mov cx, si
			mov ax, 8
			sub ax, cx
			mov [p_num], ax
			padLoop2:
				mov bx, [p_add]
				mov [bx + si], al
				inc si
				cmp si, 8
				jl padLoop2
		ret
ENDP
PROC doneBlP
	xor ax, ax
	mov bx, [p_add]
	cmp [word ptr bx], 0
	jne c_2
	add ax, 1
	c_2:
	cmp [word ptr bx + 2], 0
	jne c_3
	add ax, 1
	c_3:
	cmp [word ptr bx + 6], 0
	jne c_4
	add ax, 1
	c_4:
	cmp [word ptr bx + 4], 0
	jne c_5
	add ax, 1
	c_5:
	ret
ENDP doneBlP
;------------------------------------------------------------------------------------------------
;										FILES PROCS AND MACROS
;------------------------------------------------------------------------------------------------
PROC back8
	mov ax, 4201h
	mov bx, [filehandle]
	mov cx, 0FFFFh
	mov dx, -8
	int 21h
	ret
ENDP
PROC OpenFile ;Open file for reading and writing
	mov ah, 3Dh
	mov al, 2
	mov dx, offset filename
	int 21h
	jc openerror
	mov [filehandle], ax
	ret
	openerror:
	mov dx, offset ErrorMsg
	mov ah, 9h
	int 21h
	pop [trash]
	jmp openfl
ENDP
MACRO ReadFile BufferForData, NumOfBytes ;Read file
	mov ah, 3Fh
	mov bx, [filehandle]
	mov cx, NumOfBytes
	mov dx, offset BufferForData
	int 21h
ENDM
MACRO WriteToFile message, num ;Write message to file
	mov ah, 40h
	mov bx, [filehandle]
	mov cx, num
	mov dx, offset message
	int 21h
ENDM
PROC CloseFile ;Close file
	mov ah, 3Eh
	mov bx, [filehandle]
	int 21h
	ret
ENDP CloseFile
PROC fromEnd
	mov bx, [filehandle]
	mov dx, [p_num]
	mov cx, 0
	mov ax, 4202h
	int 21h
	ret
ENDP
;------------------------------------------------------------------------------------------------
;										GET / WRITE BIT PROCS
;------------------------------------------------------------------------------------------------
PROC get
	pop [return_address]
	push ax
	push cx
	push si
	push di
	mov ax, [gw_bits]
	mov cl, 8
	div cl
	push ax
	cbw 
	mov si, ax ;si now stores the offset in bytes
	pop ax
	shr ax, 8
	mov di, ax ;di now stores the bit offset
	mov bx, [g_address]
	mov al, [byte ptr bx + si] 
	and al, [map1 + di]
	mov cx, di
	shr al, cl
	mov [gw_bit], al
	pop di
	pop si
	pop cx
	pop ax
	push [return_address]
	ret
ENDP get
PROC writep ;saves the bit which is in w_bit in the bit position specified by w_address (address) and gw_bits (index in bits after the address).
			;label code: w
	pop [return_address]
	push ax
	push cx
	push si
	push di
	mov ax, [gw_bits]
	mov cl, 8
	div cl
	push ax
	cbw 
	mov si, ax ;si now stores the offset in bytes
	pop ax
	shr ax, 8
	mov di, ax ;di now stores the bit offset and the number of times to shift right
	mov bx, [w_address]
	mov al, [byte ptr bx + si] 
	cmp [gw_bit], 0
	je w_zero
		or al, [map1 + di]
		mov [bx + si], al
		jmp w_exit		
	w_zero:
		and al, [map2 + di]
		mov [bx + si], al		
	w_exit:
		pop di
		pop si
		pop cx
		pop ax
		push [return_address]
		ret
ENDP writep
MACRO load g_add, w_add
	lea bx, [g_add]
	mov [g_address], bx
	lea bx, [w_add]
	mov [w_address], bx
ENDM load
MACRO perm from, to, reg, map, mapLen
	local Loop
	load from, to
	xor reg, reg
	xor ax, ax
	Loop:
		mov al, [map + reg]
		dec ax
		mov [gw_bits], ax
		call get
		mov [gw_bits], reg
		call writep
		inc reg
		cmp reg, mapLen
		jl Loop
ENDM perm
;------------------------------------------------------------------------------------------------
;								CONSOLE IN/OUT PROCS AND MACROS
;------------------------------------------------------------------------------------------------
PROC lineDown
	mov dx, 0Ah
    mov ah, 2h
    int 21h
	ret
ENDP lineDown
MACRO print msg
	lea dx, [msg]
	mov ah, 9h
	int 21h
ENDM
PROC inputChar ;inputs to al a char
	mov ah, 1h
	int 21h
	ret
ENDP inputChar
MACRO  input var, num
	local ILoop1
	local I1Exit
	local ILoop2
	local ICont
	local IL1c
	push 0
	xor si, si
	ILoop1:
		call inputChar
		cmp al, 0Dh
		je I1Exit
		cmp al, 1Bh
		jne IL1c
		jmp exit
		IL1c:
		mov ah, 0
		push ax
		inc si
		cmp si, num
		jl ILoop1
	I1Exit:
		mov si, 0
		pop ax
	ILoop2: 
		sub al, 30h
		cmp al, 31h
		jl ICont
		sub al, 27h
		ICont:
		push ax
		mov ax, si
		mov cx, 2
		xor dx, dx
		div cx
		mov bx, offset var
		add bx, ax
		mov ax, dx
		mov cx, 15
		mul cx
		add ax, 1
		mov cx, ax
		pop ax
		mul cx
		add [bx], ax
		inc si
		pop ax
		cmp ax, 0
		jne ILoop2
ENDM
;------------------------------------------------------------------------------------------------
;								KEY SCHEDULE PROCS AND MACROS
;------------------------------------------------------------------------------------------------
PROC DRL
	pusha
	perm k_temp, k_temp2, di, leftRot, 56d
	mov ax, [word ptr k_temp2 + 0]
	mov [word ptr k_temp + 0], ax
	mov ax, [word ptr k_temp2 + 2]
	mov [word ptr k_temp + 2], ax
	mov ax, [word ptr k_temp2 + 4]
	mov [word ptr k_temp + 4], ax
	mov al, [byte ptr k_temp2 + 6]
	mov [byte ptr k_temp + 6], al
	popa
	ret
ENDP DRL
PROC KS
		perm key, k_temp, si, PC1, 56d
	xor si, si
	KLoop:
		call DRL
		cmp [rotMap + si], 2
		jne KCont
		call DRL
	KCont:
		lea bx, [k_temp]
		mov [g_address], bx
		mov ax, si
		push cx
		mov cx, 8
		mul cx
		pop cx
		lea bx, [subKey01]
		add ax, bx
		mov [w_address], ax
		xor di, di
		PC2Loop:
			xor ax, ax
			mov al, [PC2 + di]
			dec ax
			mov [gw_bits], ax
			call get
			mov [gw_bits], di
			call writep
			inc di
			cmp di, 48d
			jl PC2Loop
		inc si
		cmp si, 16d
		jl KLoop
	ret
ENDP KS
;------------------------------------------------------------------------------------------------
;										f Function Procs and Macros
;------------------------------------------------------------------------------------------------
PROC STLP ;sbox temp loop proc
	xor di, di
	STLoop:
		mov ax, si
		mov cx, 6
		mul cl
		add ax, di
		mov [gw_bits], ax
		call get
		mov [gw_bits], di
		call writep
		inc di
		cmp di, 6
		jne STLoop
	ret
ENDP STLP
PROC SWLP ;sbox write loop proc
	xor di, di
	SWLoop:
		mov [gw_bits], di
		call get
		mov ax, si
		mov cx, 4
		mul cl
		add ax, di
		mov [gw_bits], ax
		call writep
		inc di
		cmp di, 4
		jne SWLoop
	ret
ENDP SWLP
PROC s_cidx
	xor ax, ax
	mov al, [s_col]
	mov [s_idx], ax
	mov al, [s_line]
	mov cl, 10h
	mul cl
	add [s_idx], ax
	mov ax, si
	mov cx, 40h
	mul cl
	add [s_idx], ax
	ret
ENDP s_cidx
PROC f_xor ;xors the expanded r with the subkey according to crntKN and enc boolean
		cmp [enc], 1
		jne f_dec
		xor ax, ax
		mov al, [crntKN]
		mov cx, 8
		mul cx
		lea bx, [subKey01]
		add bx, ax
		jmp f_cont
	f_dec:
		xor ax, ax
		mov al, [crntKN]
		mov cx, 8
		mul cx
		lea bx, [subKey16]
		sub bx, ax
	f_cont:
		mov ax, [bx]
		xor [word ptr e_temp], ax
		mov ax, [bx + 2]
		xor [word ptr e_temp + 2], ax
		mov ax, [bx + 4]
		xor [word ptr e_temp + 4], ax
		ret
ENDP f_xor
PROC f_func ;Performs the f function to the 32 bits the address of which is in bx using the key the number of which is specified by crntKN
	pusha
	;------------- Expansion using E and xor -------------
		mov [g_address], bx
		lea bx, [e_temp]
		mov [w_address], bx
		xor si, si
		xor ax, ax
	ELoop:
		mov al, [E + si]
		dec ax
		mov [gw_bits], ax
		call get
		mov [gw_bits], si
		call writep
		inc si
		cmp si, 48d
		jl ELoop
		call f_xor
	;------------- sBoxes -------------
		xor si, si ;sbox iteration number
	SLoop:
		load e_temp, s_temp
		call STLP ;sbox temp loop proc
		xor ax, ax
		mov al, [s_temp]
		push ax
		and al, 00100001b
		mov cl, 10h
		div cl
		add al, ah
		cbw
		mov [s_line], al
		pop ax
		shr al, 1
		and al, 00001111b
		mov [s_col], al
		;now we have the line in s_line, the column in s_col and the table number is si + 1.
		call s_cidx
		mov di, [s_idx]
		mov al, [s1 + di]
		mov [s_temp], al
		load s_temp, s_temp2
		call SWLP ;sbox write loop proc
		inc si
		cmp si, 8
		jne SLoop
	;------------- Permutation using P -------------
		load s_temp2, f_temp
		xor si, si
		xor ax, ax
	PLoop:
		mov al, [P + si]
		dec ax
		mov [gw_bits], ax
		call get
		mov [gw_bits], si
		call writep
		inc si
		cmp si, 20h
		jl PLoop
	popa
	ret
ENDP f_func
;------------------------------------------------------------------------------------------------
;									DES and f Function Procs
;------------------------------------------------------------------------------------------------
PROC FN
	mov [n_round], 0
	NLoop:
		mov ax, [word ptr n_var]			;transferring from n_var to n_temp, all 8 bytes.
		mov [word ptr n_temp], ax
		mov ax, [word ptr n_var + 2]
		mov [word ptr n_temp + 2], ax
		mov ax, [word ptr n_var + 4]
		mov [word ptr n_temp + 4], ax
		mov ax, [word ptr n_var + 6]
		mov [word ptr n_temp + 6], ax
		mov ax, [word ptr n_var]			;transferring from r in n_var to l in n_var, 4 bytes.
		mov [word ptr n_var + 4], ax
		mov ax, [word ptr n_var + 2]
		mov [word ptr n_var + 6], ax
		lea bx, [n_temp]					;applying the f function to the r in n_temp.
		mov al, [n_round]
		mov [crntKN], al
		call f_func
		mov ax, [word ptr f_temp]			;still the f function.
		mov [word ptr n_temp], ax
		mov ax, [word ptr f_temp + 2]
		mov [word ptr n_temp + 2], ax
		mov ax, [word ptr n_temp]			;xor-ing l with r in n_temp.
		xor [word ptr n_temp + 4], ax
		mov ax, [word ptr n_temp + 2]
		xor [word ptr n_temp + 6], ax
		mov ax, [word ptr n_temp + 4]		;moving the l of n_temp to r of n_var.
		mov [word ptr n_var], ax
		mov ax, [word ptr n_temp + 6]
		mov [word ptr n_var + 2], ax
		mov al, [n_round]
		inc al
		mov [n_round], al
		cmp [n_round], 0Fh
		jl NLoop
	mov ax, [word ptr n_var]			;transferring from n_var to n_temp, all 8 bytes.
	mov [word ptr n_temp], ax
	mov ax, [word ptr n_var + 2]
	mov [word ptr n_temp + 2], ax
	mov ax, [word ptr n_var + 4]
	mov [word ptr n_temp + 4], ax
	mov ax, [word ptr n_var + 6]
	mov [word ptr n_temp + 6], ax
	lea bx, [n_temp]					;applying the f function to the r in n_temp.
	mov al, [n_round]
	mov [crntKN], al
	call f_func
	mov ax, [word ptr f_temp]			;still the f function.
	mov [word ptr n_temp], ax
	mov ax, [word ptr f_temp + 2]
	mov [word ptr n_temp + 2], ax
	mov ax, [word ptr n_temp]			;xor-ing l with r in n_temp.
	xor [word ptr n_temp + 4], ax
	mov ax, [word ptr n_temp + 2]
	xor [word ptr n_temp + 6], ax
	mov ax, [word ptr n_temp + 4]		;moving the l of n_temp to l of n_var.
	mov [word ptr n_var + 4], ax
	mov ax, [word ptr n_temp + 6]
	mov [word ptr n_var + 6], ax
	ret
ENDP FN
PROC DES
	perm block, n_var, si, IP, 64d ;Initial permutation
	call FN ;Feistel network
	perm n_var, doneBl, si, IP1, 64d ;Final permutation
	ret
ENDP DES
;------------------------------------------------------------------------------------------------
;							Modes of Operation: ECB, CBC, CFB, CTR
;------------------------------------------------------------------------------------------------
PROC ECBE
	mov [word ptr block], 0
	mov [word ptr block + 2], 0
	mov [word ptr block + 4], 0
	mov [word ptr block + 6], 0
	ReadFile block, 8
	lea bx, [block]
	mov [p_add], bx
	call pad
	call DES
	mov bx, [filehandle]
	xor cx, cx
	xor dx, dx
	mov ax, 4200h
	int 21h
	WriteToFile doneBl, 8
	cmp [lastBl], 1
	jne ecbeL
	ret
	ecbeL:
		mov [word ptr block], 0
		mov [word ptr block + 2], 0
		mov [word ptr block + 4], 0
		mov [word ptr block + 6], 0
		ReadFile block, 8
		lea bx, [block]
		mov [p_add], bx
		call pad
		cmp [done], 1
		jne ecbeLc1
		ret
		ecbeLc1:
		call DES
		cmp [lastBl], 1
		jne ecbeLc2
		call fromEnd
		ecbeLc2:
		call back8
		WriteToFile doneBl, 8
		cmp [lastBl], 1
		jne ecbeL
	ret
ENDP ECBE
PROC ECBEH
	call lineDown
	print keyMsg
	input key, 16
	call KS
	call lineDown
	print wrkMsg
	call ECBE
	print dneMsg
	jmp exit
ENDP ECBEH
PROC ECBD
	ReadFile block, 8
	call DES
	call back8
	WriteToFile doneBl, 8
	ecbdL:
		mov [word ptr block], 0
		mov [word ptr block + 2], 0
		mov [word ptr block + 4], 0
		mov [word ptr block + 6], 0
		ReadFile block, 8
		lea bx, [block]
		mov [p_add], bx
		call doneBlP
		cmp ax, 4
		jne ecbdLc
		ret
		ecbdLc:
		call DES
		call back8
		WriteToFile doneBl, 8
		jmp ecbdL
ENDP ECBD
PROC ECBDH
	call lineDown
	print keyMsg
	input key, 16
	call KS
	call lineDown
	print wrkMsg
	call ECBD
	print dneMsg
	jmp exit
ENDP ECBDH
PROC CBCE
	mov [word ptr block], 0
	mov [word ptr block + 2], 0
	mov [word ptr block + 4], 0
	mov [word ptr block + 6], 0
	ReadFile block, 8
	lea bx, [block]
	mov [p_add], bx
	call pad
	mov ax, [word ptr iv]
	xor [word ptr block], ax
	mov ax, [word ptr iv + 2]
	xor [word ptr block + 2], ax
	mov ax, [word ptr iv + 4]
	xor [word ptr block + 4], ax
	mov ax, [word ptr iv + 6]
	xor [word ptr block + 6], ax
	call DES
	mov bx, [filehandle]
	xor cx, cx
	xor dx, dx
	mov ax, 4200h
	int 21h
	WriteToFile doneBl, 8
	cmp [lastBl], 1
	jne cbceL
	ret
	cbceL:
		mov [word ptr block], 0
		mov [word ptr block + 2], 0
		mov [word ptr block + 4], 0
		mov [word ptr block + 6], 0
		ReadFile block, 8
		lea bx, [block]
		mov [p_add], bx
		call pad
		cmp [done], 1
		jne e_cont1
		ret
		e_cont1:
		mov ax, [word ptr doneBl]
		xor [word ptr block], ax
		mov ax, [word ptr doneBl + 2]
		xor [word ptr block + 2], ax
		mov ax, [word ptr doneBl + 4]
		xor [word ptr block + 4], ax
		mov ax, [word ptr doneBl + 6]
		xor [word ptr block + 6], ax
		call DES
		cmp [lastBl], 1
		jne e_cont2
		call fromEnd
		e_cont2:
		call back8
		WriteToFile doneBl, 8
		cmp [lastBl], 1
		jne cbceL
	ret
ENDP CBCE
PROC CBCEH
	call lineDown
	print keyMsg
	input key, 16
	call KS
	call lineDown
	print ivMsg
	input iv, 16
	print wrkMsg
	call CBCE
	print dneMsg
	jmp exit
ENDP CBCEH
PROC CBCD
	ReadFile block, 8
	mov ax, [word ptr block]
	mov [word ptr cbc_temp], ax
	mov ax, [word ptr block + 2]
	mov [word ptr cbc_temp + 2], ax
	mov ax, [word ptr block + 4]
	mov [word ptr cbc_temp + 4], ax
	mov ax, [word ptr block + 6]
	mov [word ptr cbc_temp + 6], ax
	call DES
	mov ax, [word ptr iv]
	xor [word ptr doneBl], ax
	mov ax, [word ptr iv + 2]
	xor [word ptr doneBl + 2], ax
	mov ax, [word ptr iv + 4]
	xor [word ptr doneBl + 4], ax
	mov ax, [word ptr iv + 6]
	xor [word ptr doneBl + 6], ax
	call back8
	WriteToFile doneBl, 8
	cbcdL:
		mov [word ptr block], 0
		mov [word ptr block + 2], 0
		mov [word ptr block + 4], 0
		mov [word ptr block + 6], 0
		ReadFile block, 8
		lea bx, [block]
		mov [p_add], bx
		call doneBlP
		cmp ax, 4
		jne cbcd_cont
		ret
		cbcd_cont:
		call DES
		mov ax, [word ptr cbc_temp]
		mov [word ptr cbc_temp + 8], ax
		mov ax, [word ptr cbc_temp + 2]
		mov [word ptr cbc_temp + 10], ax
		mov ax, [word ptr cbc_temp + 4]
		mov [word ptr cbc_temp + 12], ax
		mov ax, [word ptr cbc_temp + 6]
		mov [word ptr cbc_temp + 14], ax
		mov ax, [word ptr block]
		mov [word ptr cbc_temp], ax
		mov ax, [word ptr block + 2]
		mov [word ptr cbc_temp + 2], ax
		mov ax, [word ptr block + 4]
		mov [word ptr cbc_temp + 4], ax
		mov ax, [word ptr block + 6]
		mov [word ptr cbc_temp + 6], ax
		mov ax, [word ptr cbc_temp + 8]
		xor [word ptr doneBl], ax
		mov ax, [word ptr cbc_temp + 10]
		xor [word ptr doneBl + 2], ax
		mov ax, [word ptr cbc_temp + 12]
		xor [word ptr doneBl + 4], ax
		mov ax, [word ptr cbc_temp + 14]
		xor [word ptr doneBl + 6], ax
		call back8
		WriteToFile doneBl, 8
		jmp cbcdL
ENDP CBCD
PROC CBCDH
	call lineDown
	print keyMsg
	input key, 16
	call KS
	call lineDown
	print ivMsg
	input iv, 16
	print wrkMsg
	call CBCD
	print dneMsg
	jmp exit
ENDP CBCDH
PROC CTRE
	mov [word ptr block], 0
	mov ax, [word ptr nonce]
	mov [word ptr block + 2], ax
	mov ax, [word ptr nonce + 2]
	mov [word ptr block + 4], ax
	mov ax, [word ptr nonce + 4]
	mov [word ptr block + 6], ax
	call DES
	mov [word ptr ctr_temp], 0
	mov [word ptr ctr_temp + 2], 0
	mov [word ptr ctr_temp + 4], 0
	mov [word ptr ctr_temp + 6], 0
	ReadFile ctr_temp, 8
	lea bx, [ctr_temp]
	mov [p_add], bx
	call pad
	mov ax, [word ptr ctr_temp]
	xor [word ptr doneBl], ax
	mov ax, [word ptr ctr_temp + 2]
	xor [word ptr doneBl + 2], ax
	mov ax, [word ptr ctr_temp + 4]
	xor [word ptr doneBl + 4], ax
	mov ax, [word ptr ctr_temp + 6]
	xor [word ptr doneBl + 6], ax
	mov bx, [filehandle]
	xor cx, cx
	xor dx, dx
	mov ax, 4200h
	int 21h
	WriteToFile doneBl, 8
	cmp [lastBl], 1
	jne ctreL
	ret
	ctreL:
		inc [word ptr block]
		call DES
		mov [word ptr ctr_temp], 0
		mov [word ptr ctr_temp + 2], 0
		mov [word ptr ctr_temp + 4], 0
		mov [word ptr ctr_temp + 6], 0
		ReadFile ctr_temp, 8
		lea bx, [ctr_temp]
		mov [p_add], bx
		call pad
		cmp [done], 1
		jne ctreLc
		ret
		ctreLc:
		mov ax, [word ptr ctr_temp]
		xor [word ptr doneBl], ax
		mov ax, [word ptr ctr_temp + 2]
		xor [word ptr doneBl + 2], ax
		mov ax, [word ptr ctr_temp + 4]
		xor [word ptr doneBl + 4], ax
		mov ax, [word ptr ctr_temp + 6]
		xor [word ptr doneBl + 6], ax
		cmp [lastBl], 1
		jne ctreLc2
		call fromEnd
		ctreLc2:
		call back8
		WriteToFile doneBl, 8
		cmp [lastBl], 1
		jne ctreL
	ret
ENDP CTRE
PROC CTREH
	call lineDown
	print keyMsg
	input key, 16
	call KS
	call lineDown
	print nncMsg
	input nonce, 12
	print wrkMsg
	call CTRE
	print dneMsg
	jmp exit
ENDP CTREH
PROC CTRD
	mov [word ptr block], 0
	mov ax, [word ptr nonce]
	mov [word ptr block + 2], ax
	mov ax, [word ptr nonce + 2]
	mov [word ptr block + 4], ax
	mov ax, [word ptr nonce + 4]
	mov [word ptr block + 6], ax
	call DES
	ReadFile ctr_temp, 8
	mov ax, [word ptr ctr_temp]
	xor [word ptr doneBl], ax
	mov ax, [word ptr ctr_temp + 2]
	xor [word ptr doneBl + 2], ax
	mov ax, [word ptr ctr_temp + 4]
	xor [word ptr doneBl + 4], ax
	mov ax, [word ptr ctr_temp + 6] 
	xor [word ptr doneBl + 6], ax
	mov bx, [filehandle]
	xor cx, cx
	xor dx, dx
	mov ax, 4200h
	int 21h
	WriteToFile doneBl, 8
	ctrdL:
		inc [word ptr block]
		mov ax, [word ptr nonce]
		mov [word ptr block + 2], ax
		mov ax, [word ptr nonce + 2]
		mov [word ptr block + 4], ax
		mov ax, [word ptr nonce + 4]
		mov [word ptr block + 6], ax
		call DES
		mov [word ptr ctr_temp], 0
		mov [word ptr ctr_temp + 2], 0
		mov [word ptr ctr_temp + 4], 0
		mov [word ptr ctr_temp + 6], 0
		ReadFile ctr_temp, 8
		lea bx, [ctr_temp]
		mov [p_add], bx
		call doneBlP
		cmp ax, 4
		jne ctrdLc
		ret
		ctrdLc:
		mov ax, [word ptr ctr_temp]
		xor [word ptr doneBl], ax
		mov ax, [word ptr ctr_temp + 2]
		xor [word ptr doneBl + 2], ax
		mov ax, [word ptr ctr_temp + 4]
		xor [word ptr doneBl + 4], ax
		mov ax, [word ptr ctr_temp + 6]
		xor [word ptr doneBl + 6], ax
		call back8
		WriteToFile doneBl, 8
		jmp ctrdL
ENDP CTRD
PROC CTRDH
	mov [enc], 1
	call lineDown
	print keyMsg
	input key, 16
	call KS
	call lineDown
	print nncMsg
	input nonce, 12
	print wrkMsg
	call CTRD
	print dneMsg
	jmp exit
ENDP CTRDH
;																												  __  __       _           
;																												 |  \/  |     (_)        _ 
;																												 | \  / | __ _ _ _ __   (_)
;																												 | |\/| |/ _` | | '_ \     
;																												 | |  | | (_| | | | | |  _ 
;																												 |_|  |_|\__,_|_|_| |_| (_)
	start:
	mov ax, @data
	mov ds, ax
	call lineDown
	print WlcMsg
	call lineDown
	openfl:
	call inputChar
	cmp al, 1Bh
	jne scnt
	jmp exit
	scnt:
	call OpenFile
	call lineDown
	ch1:
	print ch1Msg
	call inputChar
	cmp al, 'e'
	je encl
	cmp al, 'd'
	je decl
	cmp al, 1Bh
	jne cont
	jmp exit
	cont:
	jmp ch1
encl:
	mov [enc], 1
	call lineDown
	print modMsg
	call inputChar
	cmp al, '1'
	je ecb_enc
	cmp al, '2'
	je cbc_enc
	cmp al, '3'
	je ctr_enc
	cmp al, 1Bh
	jne encl
	jmp exit
	ecb_enc:
		call ECBEH
	cbc_enc:
		call CBCEH
	ctr_enc:
		call CTREH
decl:
	mov [enc], 0
	call lineDown
	print modMsg
	call inputChar
	cmp al, '1'
	je ecb_dec
	cmp al, '2'
	je cbc_dec
	cmp al, '3'
	je ctr_dec
	cmp al, 1Bh
	jne encl
	jmp exit
	ecb_dec:
		call ECBDH
	cbc_dec:
		call CBCDH
	ctr_dec:
		call CTRDH
exit:
	call CloseFile
    mov ax, 4c00h
    int 21h
END start