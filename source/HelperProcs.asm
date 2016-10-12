;============================================
; HelperProcs.asm file
;============================================
.486
.model flat, C
option casemap :none

.code

GetPEB PROC
	assume fs:nothing
	mov eax, dword ptr fs:[30h]
	assume fs:error
	ret
GetPEB ENDP

GetCurrentAddress PROC
	call L1
	L1 : pop eax
	ret
GetCurrentAddress ENDP



END