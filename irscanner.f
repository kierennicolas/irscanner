C ================================================================
C  IRSCANNER.F  -  Incident Response Binary Triage Tool v1.0
C  Language : Fortran 77 (with common extensions: GETARG,
C             IMPLICIT NONE, LEN_TRIM - all supported by gfortran)
C
C  PURPOSE  : First-pass triage of suspicious binary files during
C             incident response. Runs on any host with a gfortran
C             static binary - no runtime, no dependencies.
C
C  ANALYSES :
C    1. Global Shannon entropy   (detects packing/encryption)
C    2. Sliding-window entropy   (locates high-entropy regions)
C    3. Byte frequency table     (XOR key candidate detection)
C    4. Byte diversity           (shellcode sled indicator)
C    5. Run-length analysis      (NOP sled / heap spray detection)
C    6. Top-5 byte frequencies   (dominant byte fingerprint)
C
C  COMPILE  :
C    gfortran -std=legacy -O2 -static-libgfortran \
C             -o irscanner irscanner.f
C
C  USAGE    :
C    ./irscanner <target_file>   >  report.txt
C
C  NOTE     : Output is fixed-width plain text; suitable for
C             chain-of-custody documentation. Deterministic:
C             identical input always produces identical output.
C ================================================================
      PROGRAM SCANNER
      IMPLICIT NONE

C ----------------------------------------------------------------
C  I/O unit number
C ----------------------------------------------------------------
      INTEGER UNIT
      PARAMETER (UNIT = 10)

C ----------------------------------------------------------------
C  Sliding-window parameters
C ----------------------------------------------------------------
      INTEGER WINSZ
      PARAMETER (WINSZ = 512)

C ----------------------------------------------------------------
C  Variable declarations  (Fortran 77: all at top)
C ----------------------------------------------------------------
      CHARACTER*1   BYTE
      CHARACTER*255 FNAME
      INTEGER       IERR, RECNO, FNLEN
      INTEGER       I, J
      INTEGER       IBYTE, PREVBYT

C     Byte frequency table (indices 0..255)
      INTEGER       FREQ(0:255)
      INTEGER       FREQCPY(0:255)

C     File totals
      INTEGER       TOTBYTES

C     Entropy (global)
      REAL          GENT, P

C     Sliding-window entropy
      INTEGER       WBUF(0:511)     ! circular buffer of byte values
      INTEGER       WFREQ(0:255)    ! per-window frequency table
      INTEGER       WPOS            ! write head in circular buffer
      INTEGER       WFILL           ! bytes loaded into window so far
      INTEGER       WOLD            ! byte being evicted
      REAL          WENT            ! current window entropy
      REAL          MAXWENT         ! highest window entropy seen
      INTEGER       MAXWPOS         ! file position of that window
      REAL          MINWENT         ! lowest window entropy
      INTEGER       MINWPOS

C     XOR / frequency
      INTEGER       MAXFREQ, XORKEY
      REAL          PCTDOM, PCTNUL

C     Byte diversity
      INTEGER       UNIQUE

C     Run-length detection
      INTEGER       RUNLEN, MAXRUN, RUNBYTE, RUNSTART
      INTEGER       CURRUN, CURBYTE

C     Scratch
      REAL          SCRATCH

C ================================================================
C  HEADER BANNER
C ================================================================
      WRITE(*,'(A)')
     +'  ======================================================='
      WRITE(*,'(A)')
     +'  IRSCANNER v1.0  |  IR Binary Triage  |  Fortran 77'
      WRITE(*,'(A)')
     +'  ======================================================='

C ================================================================
C  READ FILENAME FROM COMMAND LINE
C ================================================================
      CALL GETARG(1, FNAME)
      IF (FNAME(1:1) .EQ. ' ') THEN
        WRITE(*,'(A)') '  USAGE: irscanner <target_file>'
        STOP
      END IF
      FNLEN = LEN_TRIM(FNAME)

      WRITE(*,'(A,A)') '  TARGET : ', FNAME(1:FNLEN)
      WRITE(*,*)

C ================================================================
C  INITIALISE COUNTERS
C ================================================================
      DO I = 0, 255
        FREQ(I)  = 0
        WFREQ(I) = 0
      END DO
      DO I = 0, WINSZ-1
        WBUF(I) = 0
      END DO

      TOTBYTES = 0
      MAXRUN   = 0
      RUNLEN   = 1
      RUNBYTE  = 0
      RUNSTART = 0
      CURRUN   = 0
      CURBYTE  = 0
      PREVBYT  = -1
      WPOS     = 0
      WFILL    = 0
      MAXWENT  = -1.0
      MAXWPOS  = 0
      MINWENT  = 9.0
      MINWPOS  = 0

C ================================================================
C  OPEN FILE  (direct access, 1 byte per record)
C  RECL=1 means 1 byte per record in gfortran direct mode.
C ================================================================
      OPEN(UNIT=UNIT, FILE=FNAME(1:FNLEN),
     +     ACCESS='DIRECT', RECL=1,
     +     FORM='UNFORMATTED', STATUS='OLD',
     +     IOSTAT=IERR)

      IF (IERR .NE. 0) THEN
        WRITE(*,'(A)') '  [ERROR] Cannot open file.'
        STOP
      END IF

C ================================================================
C  MAIN READ LOOP  - single pass
C ================================================================
      RECNO = 1

  100 CONTINUE
        READ(UNIT, REC=RECNO, IOSTAT=IERR) BYTE
        IF (IERR .NE. 0) GOTO 200

C       Convert CHARACTER*1 -> integer 0..255
        IBYTE = ICHAR(BYTE)
        IF (IBYTE .LT. 0) IBYTE = IBYTE + 256

        TOTBYTES       = TOTBYTES + 1
        FREQ(IBYTE)    = FREQ(IBYTE) + 1

C       ---- Run-length tracking --------------------------------
        IF (TOTBYTES .EQ. 1) THEN
          CURRUN   = 1
          CURBYTE  = IBYTE
          RUNSTART = 1
        ELSE IF (IBYTE .EQ. CURBYTE) THEN
          CURRUN = CURRUN + 1
        ELSE
          IF (CURRUN .GT. MAXRUN) THEN
            MAXRUN   = CURRUN
            RUNBYTE  = CURBYTE
            RUNSTART = TOTBYTES - CURRUN
          END IF
          CURBYTE  = IBYTE
          CURRUN   = 1
        END IF

C       ---- Sliding-window entropy -----------------------------
C       Evict old byte from window frequency table
        IF (WFILL .GE. WINSZ) THEN
          WOLD = WBUF(WPOS)
          WFREQ(WOLD) = WFREQ(WOLD) - 1
        END IF

C       Insert new byte into window
        WBUF(WPOS)    = IBYTE
        WFREQ(IBYTE)  = WFREQ(IBYTE) + 1
        WPOS          = MOD(WPOS + 1, WINSZ)
        IF (WFILL .LT. WINSZ) WFILL = WFILL + 1

C       Compute window entropy only once window is full
        IF (WFILL .EQ. WINSZ) THEN
          WENT = 0.0
          DO I = 0, 255
            IF (WFREQ(I) .GT. 0) THEN
              P    = FLOAT(WFREQ(I)) / FLOAT(WINSZ)
              WENT = WENT - P * LOG(P) / LOG(2.0)
            END IF
          END DO
          IF (WENT .GT. MAXWENT) THEN
            MAXWENT = WENT
            MAXWPOS = TOTBYTES - WINSZ + 1
          END IF
          IF (WENT .LT. MINWENT) THEN
            MINWENT = WENT
            MINWPOS = TOTBYTES - WINSZ + 1
          END IF
        END IF

        RECNO = RECNO + 1
      GOTO 100
  200 CONTINUE
      CLOSE(UNIT)

C     Flush final run
      IF (CURRUN .GT. MAXRUN) THEN
        MAXRUN   = CURRUN
        RUNBYTE  = CURBYTE
        RUNSTART = TOTBYTES - CURRUN + 1
      END IF

C ================================================================
C  GUARD: empty file
C ================================================================
      IF (TOTBYTES .EQ. 0) THEN
        WRITE(*,'(A)') '  [ERROR] File is empty or unreadable.'
        STOP
      END IF

C ================================================================
C  SECTION 1  -  FILE SUMMARY
C ================================================================
      WRITE(*,'(A)')
     +'  --- FILE SUMMARY -----------------------------------'
      WRITE(*,'(A,I12,A)') '  BYTES    : ', TOTBYTES, ' bytes'
      WRITE(*,*)

C ================================================================
C  SECTION 2  -  GLOBAL SHANNON ENTROPY
C ================================================================
      GENT = 0.0
      DO I = 0, 255
        IF (FREQ(I) .GT. 0) THEN
          P    = FLOAT(FREQ(I)) / FLOAT(TOTBYTES)
          GENT = GENT - P * LOG(P) / LOG(2.0)
        END IF
      END DO

      WRITE(*,'(A)')
     +'  --- ENTROPY ANALYSIS (GLOBAL) ----------------------'
      WRITE(*,'(A,F6.4,A)') '  ENTROPY  : ', GENT,
     +' bits/byte   [max = 8.0000]'

      IF (GENT .GT. 7.2) THEN
        WRITE(*,'(A)')
     +'  RESULT   : [!!] HIGH    - encrypted, packed, or'//
     +' compressed'
      ELSE IF (GENT .GT. 6.0) THEN
        WRITE(*,'(A)')
     +'  RESULT   : [! ] ELEVATED - obfuscation likely'
      ELSE IF (GENT .GT. 4.0) THEN
        WRITE(*,'(A)')
     +'  RESULT   : [~ ] MODERATE - mixed content, check struct'
      ELSE
        WRITE(*,'(A)')
     +'  RESULT   : [OK] LOW      - plaintext or structured data'
      END IF
      WRITE(*,*)

C ================================================================
C  SECTION 3  -  SLIDING-WINDOW ENTROPY (highest & lowest regions)
C ================================================================
      WRITE(*,'(A)')
     +'  --- ENTROPY ANALYSIS (SLIDING WINDOW, sz=512B) -----'

      IF (TOTBYTES .GE. WINSZ) THEN
        WRITE(*,'(A,F6.4,A,I10)')
     +'  MAX WENT : ', MAXWENT,
     +'  at byte offset ~', MAXWPOS
        WRITE(*,'(A,F6.4,A,I10)')
     +'  MIN WENT : ', MINWENT,
     +'  at byte offset ~', MINWPOS

        IF (MAXWENT .GT. 7.2) THEN
          WRITE(*,'(A)')
     +'  RESULT   : [!!] High-entropy region found - likely'//
     +' packed payload or cipher blob'
        ELSE
          WRITE(*,'(A)')
     +'  RESULT   : [OK] No localised high-entropy region'
        END IF
      ELSE
        WRITE(*,'(A)')
     +'  RESULT   : [--] File smaller than window size, skipped'
      END IF
      WRITE(*,*)

C ================================================================
C  SECTION 4  -  BYTE FREQUENCY & XOR KEY CANDIDATE DETECTION
C ================================================================
      MAXFREQ = 0
      XORKEY  = 0
      DO I = 0, 255
        IF (FREQ(I) .GT. MAXFREQ) THEN
          MAXFREQ = FREQ(I)
          XORKEY  = I
        END IF
      END DO

      PCTDOM = 100.0 * FLOAT(MAXFREQ)   / FLOAT(TOTBYTES)
      PCTNUL = 100.0 * FLOAT(FREQ(0))  / FLOAT(TOTBYTES)

      WRITE(*,'(A)')
     +'  --- BYTE FREQUENCY / XOR CANDIDATE -----------------'
      WRITE(*,'(A,I3,A,I3,A,F5.1,A)')
     +'  DOMINANT : 0x', XORKEY,
     +' (dec ', XORKEY, ', ', PCTDOM, '% of file)'
      WRITE(*,'(A,F5.1,A)')
     +'  NULL PCT : ', PCTNUL, '% null bytes (0x00)'

      IF (XORKEY .NE. 0 .AND. PCTDOM .GT. 15.0) THEN
        WRITE(*,'(A,I3,A)')
     +'  RESULT   : [!!] Single-byte XOR candidate: 0x',
     + XORKEY, ' - check XOR-decoded output'
      ELSE IF (XORKEY .EQ. 0 .AND. PCTNUL .GT. 30.0) THEN
        WRITE(*,'(A)')
     +'  RESULT   : [~ ] Null-dominant - sparse binary or'//
     +' aligned data structure'
      ELSE
        WRITE(*,'(A)')
     +'  RESULT   : [OK] No strong single-byte XOR signature'
      END IF
      WRITE(*,*)

C ================================================================
C  SECTION 5  -  BYTE DIVERSITY
C ================================================================
      UNIQUE = 0
      DO I = 0, 255
        IF (FREQ(I) .GT. 0) UNIQUE = UNIQUE + 1
      END DO

      WRITE(*,'(A)')
     +'  --- BYTE DIVERSITY ----------------------------------'
      WRITE(*,'(A,I4,A)') '  UNIQUE   : ', UNIQUE,
     +' distinct byte values (of 256)'

      IF (UNIQUE .LT. 16) THEN
        WRITE(*,'(A)')
     +'  RESULT   : [!!] VERY LOW  - shellcode sled or heavily'//
     +' encoded payload strongly suspected'
      ELSE IF (UNIQUE .LT. 64) THEN
        WRITE(*,'(A)')
     +'  RESULT   : [! ] LOW       - restricted charset,'//
     +' possible base-N or custom encoding'
      ELSE IF (UNIQUE .LT. 128) THEN
        WRITE(*,'(A)')
     +'  RESULT   : [~ ] MODERATE  - printable-range bias'
      ELSE
        WRITE(*,'(A)')
     +'  RESULT   : [OK] NORMAL    - full byte space in use'
      END IF
      WRITE(*,*)

C ================================================================
C  SECTION 6  -  RUN-LENGTH / SLED DETECTION
C ================================================================
      WRITE(*,'(A)')
     +'  --- SLED & REPEAT PATTERN DETECTION ----------------'
      WRITE(*,'(A,I8,A)')
     +'  MAX RUN  : ', MAXRUN,
     +' consecutive identical bytes'
      WRITE(*,'(A,I3,A,I3)')
     +'  RUN BYTE : 0x', RUNBYTE, '  (decimal ', RUNBYTE, ')'
      WRITE(*,'(A,I10)')
     +'  AT BYTE  : ~', RUNSTART

      IF (RUNBYTE .EQ. 144 .AND. MAXRUN .GT. 15) THEN
        WRITE(*,'(A)')
     +'  RESULT   : [!!] 0x90 (NOP) sled detected - classic'//
     +' shellcode staging indicator'
      ELSE IF (RUNBYTE .EQ. 0 .AND. MAXRUN .GT. 64) THEN
        WRITE(*,'(A)')
     +'  RESULT   : [! ] Long null run - possible heap-spray'//
     +' or initialised buffer fill'
      ELSE IF (MAXRUN .GT. 64) THEN
        WRITE(*,'(A)')
     +'  RESULT   : [! ] Long repetitive region - investigate'//
     +' surrounding bytes'
      ELSE IF (MAXRUN .GT. 15) THEN
        WRITE(*,'(A)')
     +'  RESULT   : [~ ] Moderate run - minor anomaly'
      ELSE
        WRITE(*,'(A)')
     +'  RESULT   : [OK] No significant repetitive sleds'
      END IF
      WRITE(*,*)

C ================================================================
C  SECTION 7  -  TOP 5 BYTE VALUES
C  (We work on a copy of FREQ so the original is preserved)
C ================================================================
      DO I = 0, 255
        FREQCPY(I) = FREQ(I)
      END DO

      WRITE(*,'(A)')
     +'  --- TOP 5 BYTE FREQUENCIES -------------------------'
      WRITE(*,'(A)')
     +'  RANK  HEX   DEC    COUNT        PCT'
      WRITE(*,'(A)')
     +'  ----  ----  ---  ---------  -------'

      DO J = 1, 5
        MAXFREQ = 0
        XORKEY  = 0
        DO I = 0, 255
          IF (FREQCPY(I) .GT. MAXFREQ) THEN
            MAXFREQ = FREQCPY(I)
            XORKEY  = I
          END IF
        END DO
        IF (MAXFREQ .EQ. 0) GOTO 300
        PCTDOM = 100.0 * FLOAT(MAXFREQ) / FLOAT(TOTBYTES)
        WRITE(*,'(A,I2,A,I3,A,I4,A,I10,A,F6.2,A)')
     +'  #', J, '    0x', XORKEY,
     +'  ', XORKEY, '  ', MAXFREQ,
     +'     ', PCTDOM, '%'
        FREQCPY(XORKEY) = 0
      END DO
  300 CONTINUE
      WRITE(*,*)

C ================================================================
C  FOOTER
C ================================================================
      WRITE(*,'(A)')
     +'  ======================================================='
      WRITE(*,'(A)')
     +'  END OF REPORT  |  Deterministic & repeatable output'
      WRITE(*,'(A)')
     +'  ======================================================='

      STOP
      END
