;============================================
; HelperProcs.asm file
;============================================
.486
.model flat, C
option casemap :none

.code

; Most of this procedure was code-generated from Visual C++
; Needs stepping through to ensure that the module base address being fetched is correct
Entry PROC
	ASSUME FS:NOTHING
	CALL CURRENTADDR
	CURRENTADDR : POP DWORD PTR SS:[EBP-0Ch]
	MOV EAX,DWORD PTR FS:[30h]
	MOV DWORD PTR SS:[EBP-24h], EAX
	MOV EAX,DWORD PTR SS:[EBP-24h]
	MOV ECX,DWORD PTR DS:[EAX+0Ch]
	MOV EDX,DWORD PTR DS:[ECX+0Ch]
	MOV DWORD PTR SS:[EBP-24h], EDX
	SEARCHPEB: 
		MOV EAX,DWORD PTR SS:[EBP-24h]
		CMP DWORD PTR DS:[EAX+18h], 0h
			JE SHORT ENDLOOP
		MOV EAX,DWORD PTR SS:[EBP-24h]
		MOV ECX,DWORD PTR DS:[EAX+18h]
		MOV DWORD PTR SS:[EBP-30h],ECX
		MOV EAX,DWORD PTR SS:[EBP-0Ch]
		SUB EAX,DWORD PTR SS:[EBP-30h]
		MOV DWORD PTR SS:[EBP-3Ch],EAX
		MOV EAX,DWORD PTR SS:[EBP-30h]
		ADD EAX,DWORD PTR SS:[EBP-3Ch]
		CMP EAX,DWORD PTR SS:[EBP-0Ch]
			JNE SHORT COND
		MOV EAX,DWORD PTR SS:[EBP-30h]
		MOV DWORD PTR SS:[EBP-18h],EAX
		JMP SHORT ENDLOOP
		COND: 
			MOV EAX,DWORD PTR SS:[EBP-24h]
			MOV ECX,DWORD PTR DS:[EAX]
			MOV DWORD PTR SS:[EBP-24h],ECX
			JMP SHORT SEARCHPEB
	ENDLOOP:
		MOV EDX,DWORD PTR SS:[EBP-18h]
		MOV EAX, 000001563h		; Hard coded OEP constant. Will need to replace
		OR EDX,EAX
		JMP EDX
	ASSUME FS:ERROR
Entry ENDP
	
EntryPtr PROC
	RET
EntryPtr ENDP

END