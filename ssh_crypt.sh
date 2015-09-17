#!/bin/env sh

[ $# -eq 0 ] && { cat <<EOF
Usage:
`basename $0`

EOF
exit 0
}

MODE=""
INFILE=""
OUTFILE=""

PRIVKEY=""
PRIV_KEY_TYPE=""
NEW_PRIV_KEY=""

PUBKEY=""
PUB_KEY_TYPE=""
NEW_PUB_KEY=""

SIGN=""
ARMOR=""

VERBOSE=0

SINATURE=""
COMPRESSED=""

DIRTY=""
DELETE_OUTFILE=""

RNDSRC="/dev/urandom"

# if you want to convert your private key to PKCS#8 format,
# use the following command:
# openssl pkcs8 -topk8 -v2 aes256 -in <old_ssh_PEM_key> -out <new_PKCS8_key>

CleanUpTempFiles() {
    if [ "$DIRTY" ]; then
        LogMessage "Cleaning up some temporary files..." 3
        [ "$NEW_PUB_KEY" ] && {
            [ -f "$NEW_PUB_KEY" ] && rm -f $NEW_PUB_KEY;
        }
        [ "$NEW_PRIV_KEY" ] && {
            [ -f "$NEW_PRIV_KEY" ] && rm -f $NEW_PRIV_KEY;
        }
        [ -f "$COMPRESSED" ] && rm -f "$COMPRESSED"
        [ -f xx00 ] && rm -f xx*
        [ -f "$SIGNATURE" ] && rm -f "$SIGNATURE"
        [ -f "$DATAFILE" ] && rm -f "$DATAFILE"
        [ -f "$DELETE_OUTFILE" ] && rm -f "$DELETE_OUTFILE"
        DIRTY=""
    fi
}

OnExit() {
    CleanUpTempFiles
    LogMessage "Exit." 3
}

OnInt() {
    LogMessage "SIGINT Caught" 3
    LogMessage "All is under the control" 4
}

OnAbrt() {
    LogMessage "SIGABRT Caught" 3
    CleanUpTempFiles
}

OnTerm() {
    LogMessage "SIGTERM Caught" 3
    CleanUpTempFiles
}

OnQuit() {
    LogMessage "SIGQUIT Caught" 3
    CleanUpTempFiles
}

OnKill() {
    LogMessage "SIGKILL Caught" 3
    CleanUpTempFiles
}

trap OnExit EXIT
trap OnInt  INT
trap OnAbrt ABRT
trap OnTerm TERM
trap OnQuit QUIT
trap OnKill KILL

LogMessage() {
    [ $# -eq 0 -o $# -gt 2 ] && return 0

    while [ "$1" ]; do
        case "$1" in
            [0-9]|[0-9][0-9])
                [ $VERBOSE -lt $1 ] && return 0
                ;;
            *)
                MESSAGE="$1"
                ;;
        esac
        shift
    done
    echo "$MESSAGE"
}

ConvertPrivateKeyToPKCS8() {
    [ -f "$PRIVKEY.pkcs8" ] && {
        PRIVKEY="$PRIVKEY.pkcs8"
        NEW_PRIVKEY=""
    } || {
        LogMessage "Converting private key to openssl-compatible format" 1
        openssl pkcs8 -topk8 -v2 aes256 -in "$PRIVKEY" -out "$PRIVKEY.pkcs8"
        NEW_PRIV_KEY="$PRIVKEY.pkcs8"
        DIRTY="1"
    }
}

GetPrivateKey() {
    if [ -z "$PRIVKEY" ]; then
        if [ "$MODE" = "dec" ]; then
            LogMessage "You sould provide private key to decrypt data."
            exit 1
        else
            LogMessage "You chose to sign data, but I can't do it," 1
            LogMessage "because private key parameter is empty." 1
            LogMessage "Continue as is." 2
            return 1
        fi
    fi
    HEAD=`head -n 1 $PRIVKEY`
    FIRST_FIELD=`echo $HEAD | cut -c 1-3`
    case "$FIRST_FIELD" in
        ---)
            SECOND_FIELD=`echo $HEAD | cut -d ' ' -f 2`
            case "$SECOND_FIELD" in
                OPENSSH) # ed25519
                    PRIV_KEY_TYPE="INVALID"
                    ;;
                EC)
                    PRIV_KEY_TYPE="ECDSA-PEM"
                    ;;
                DSA)
                    PRIV_KEY_TYPE="DSA-PEM"
                    ;;
                RSA)
                    PRIV_KEY_TYPE="RSA-PEM"
                    ;;
                ENCRYPTED)
                    PRIV_KEY_TYPE="PKCS8"
                    ;;
                *)
                    PRIV_KEY_TYPE="INVALID"
            esac
            ;;
        *)
            PRIV_KEY_TYPE="INVALID"
    esac
    case "$PRIV_KEY_TYPE" in
        ECDSA-PEM)
            [ "$MODE" = "dec" ] && {
                LogMessage "Can't use ECDSA private key for decryption"
                exit 4
            }
#            ConvertPrivateKeyToPKCS8
            ;;
        DSA-PEM)
            [ "$MODE" = "dec" ] && {
                LogMessage "Can't use DSA private key for decryption"
                exit 4
            }
#            ConvertPrivateKeyToPKCS8
            ;;
        PKCS8|RSA-PEM)
            NEW_PRIV_KEY=""
            ;;
        *)
            LogMessage "Private key type not supported."
            LogMessage "Must be RSA (PEM or PKCS8)." 1
            [ "$MODE" = "enc" ] && {
                PRIVKEY=""
                return 2
            } || exit 2
    esac
    return 0
}

GetPublicKey() {
    if [ -z "$PUBKEY" ]; then
        if [ "$MODE" = "enc" ]; then
            LogMessage "You sould provide public key to encrypt data."
            exit 1
        else
            LogMessage "Encrypted data are digitally signed, but I can't verify" 1
            LogMessage "the signature, because public key parameter is empty." 1
            LogMessage "Continue as is." 2
            return 1
        fi
    fi
    HEAD=`head -n 1 $PUBKEY`
    FIRST_FIELD=`echo $HEAD | cut -c 1-5`
    case "$FIRST_FIELD" in
        -----)
            SECOND_FIELD=`echo $HEAD | cut -d ' ' -f 2`
            case "$SECOND_FIELD" in
                RSA)
                    PUB_KEY_TYPE="PEM"
                    ;;
                PUBLIC)
                    PUB_KEY_TYPE="PKCS8"
                    ;;
                *)
                    PUB_KEY_TYPE="INVALID"
            esac
            ;;
        ssh-r)
            PUB_KEY_TYPE="SSH2"
            ;;
        ssh-d)
            PUB_KEY_TYPE="SSH2"
            [ "$MODE" = "enc" ] && {
                LogMessage "Can't use DSA public key for encryption"
                exit 4
            }
            ;;
        ecdsa)
            PUB_KEY_TYPE="SSH2"
            [ "$MODE" = "enc" ] && {
                LogMessage "Can't use ECDSA public key for encryption"
                exit 4
            }
            ;;
        ssh-e) # ed25519
            PUB_KEY_TYPE="INVALID"
            ;;
        *)
            PUB_KEY_TYPE="INVALID"
    esac
    case "$PUB_KEY_TYPE" in
        SSH2)
            [ -f "$PUBKEY.pkcs8" ] && {
                PUBKEY="$PUBKEY.pkcs8"
                NEW_PUB_KEY=""
                LogMessage "Key $PUBKEY found" 3
            } || {
                NEW_PUB_KEY="$PUBKEY.pkcs8"
                LogMessage "Converting $PUBKEY to $NEW_PUB_KEY..." 2
                ssh-keygen -f "$PUBKEY" -e -m "PKCS8" >"$NEW_PUB_KEY"
                DIRTY="1"
            }
            ;;
        PEM)
            [ -f "$PUBKEY.pkcs8" ] && {
                PUBKEY="$PUBKEY.pkcs8"
                NEW_PUB_KEY=""
                LogMessage "Key $PUBKEY found" 3
            } || {
                NEW_PUB_KEY="$PUBKEY.pkcs8"
                LogMessage "Converting $PUBKEY to $NEW_PUB_KEY..." 2
                openssl rsa -RSAPublicKey_in -in "$PUBKEY" -pubout -out "$NEW_PUB_KEY"
                DIRTY="1"
            }
            ;;
        PKCS8)
            NEW_PUB_KEY=""
            ;;
        *)
            LogMessage "Public key type not supported."
            LogMessage "Must be RSA (RFC 4716/SSH2, PEM or PEM PKCS8)." 1
            [ "$MODE" = "dec" ] && {
                PUBKEY=""
                return 2
            } || exit 2
    esac
    return 0
}


while [ $# -gt 0 ]; do
    case "$1" in
        --enc|-e)
            [ -z "$MODE" ] && MODE="enc"
            ;;
        --dec|-d)
            [ -z "$MODE" ] && MODE="dec"
            ;;
        --pub|-p)
            shift
            if [ -z "$PUBKEY" ]; then
                if [ -f "$1" ]; then
                    PUBKEY="$1"
                else
                    LogMessage "Can't find public key file $1"
                fi
            fi
            ;;
        --pub=*)
            VAL=`echo "$1" | cut -c 7-`
            if [ -z "$PUBKEY" ]; then
                if [ -f "$VAL" ]; then
                    PUBKEY="$VAL"
                else
                    LogMessage "Can't find public key file $VAL"
                fi
            fi
            ;;
        --priv|-k)
            shift
            if [ -z "$PRIVKEY" ]; then
                if [ -f "$1" ]; then
                    PRIVKEY="$1"
                else
                    LogMessage "Can't find private key file $1"
                fi
            fi
            ;;
        --priv=*)
            VAL=`echo "$1" | cut -c 8-`
            if [ -z "$PRIVKEY" ]; then
                if [ -f "$VAL" ]; then
                    PRIVKEY="$VAL"
                else
                    LogMessage "Can't find private key file $VAL"
                fi
            fi
            ;;
        --sign|-s)
            SIGN="1"
            ;;
        --armor|-a)
            ARMOR="1"
            ;;
        --verbose|-v)
            VERBOSE=$((VERBOSE+1))
            ;;
        *)
            if [ "`echo $1 | cut -c 1-2`" = "--" ]; then
                LogMessage "Invalid option: $1"
            elif [ -z "$INFILE" ]; then
                INFILE="$1"
            else
                if [ -z "$OUTFILE" ]; then
                    OUTFILE="$1"
                fi
            fi
    esac
    shift
done

[ $VERBOSE -gt 0 ] && echo "Verbosity level set to $VERBOSE"

[ "$INFILE" -a -f "$INFILE" ] || {
    LogMessage "Invalid input file $INFILE"
    exit 1
}

[ -z "$MODE" ] && MODE="enc"


if [ "$MODE" = "enc" ]; then
    if [ "$SIGN" ]; then
        GetPrivateKey
        [ "$NEW_PRIV_KEY" ] && PRIVKEY=$NEW_PRIV_KEY
    fi
    GetPublicKey
    [ $NEW_PUB_KEY ] && {
        PUBKEY=$NEW_PUB_KEY
        AGE="new "
    } || {
        AGE="original "
    }
    LogMessage "Using $AGE$PUBKEY for encryption." 3
    # max. data size for different padding schemes:
    #  - pkcs#1 v1.5 (default) & ssl: ≤ 245 bytes
    #  - pkcs#1 oaep: ≤ 214 bytes
    #  - raw: ≤ 256 bytes
    export SESSION_KEY="`head -c 213 $RNDSRC`"
    gzip -k -f "$INFILE"
    COMPRESSED="$INFILE.gz"
    DIRTY="1"
    if [ "$ARMOR" ]; then
        OUT_EXT="asc"
        [ -z "$OUTFILE" ] && OUTFILE=$INFILE.$OUT_EXT
        LogMessage "Encrypting data..."
        ENCODED_NAME=`echo $INFILE | openssl aes-256-ofb -nosalt -pass env:SESSION_KEY | base64`
        echo "-----BEGIN ENCRYPTED DATA: $ENCODED_NAME-----" >"$OUTFILE"
        openssl aes-256-ofb -pass env:SESSION_KEY -in "$COMPRESSED" | base64 >>"$OUTFILE"
        echo "-----END ENCRYPTED DATA-----" >>"$OUTFILE"
        echo "" >>"$OUTFILE"
        LogMessage "Encrypting session key..." 2
        echo "-----BEGIN SESSION KEY-----" >>"$OUTFILE"
        echo -n "$SESSION_KEY" | openssl rsautl -encrypt -pubin -inkey $PUBKEY -oaep | base64 >>"$OUTFILE" || {
            LogMessage "Fatal: Can't encrypt session key"
            DELETE_OUTFILE="1"
            exit 3
        }
        echo "-----END SESSION KEY-----" >>"$OUTFILE"
        if [ "$SIGN" ]; then
            if [ "$PRIVKEY" ]; then
                LogMessage "Signing data..."
                SIGNATURE=`openssl sha512 -sign "$PRIVKEY" -binary "$INFILE" || echo ""`
                if [ "$SIGNATURE" ]; then
                    echo "" >>"$OUTFILE"
                    echo "-----BEGIN DIGITAL SIGNATURE-----" >>"$OUTFILE"
                    echo "$SIGNATURE" | base64 >>"$OUTFILE"
                    echo "-----END DIGITAL SIGNATURE-----" >>"$OUTFILE"
                else
                    LogMessage "Warning: Can't sign the data" 1
                    LogMessage "Continue without signature" 2
                fi
            else
                LogMessage "Warning: Can't sign the data without proper private key." 1
            fi
        fi
    else
        OUT_EXT="bin"
        [ -z "$OUTFILE" ] && OUTFILE=$INFILE.$OUT_EXT
        LogMessage "Encrypting data..."
        ENCODED_NAME=`echo $INFILE | openssl aes-256-ofb -nosalt -pass env:SESSION_KEY`
        echo "N.....,_" >"$OUTFILE"
        echo "$ENCODED_NAME" >>"$OUTFILE"
        echo "" >>"$OUTFILE"
        echo "D.....,_" >>"$OUTFILE"
        openssl aes-256-ofb -pass env:SESSION_KEY -in "$COMPRESSED" >>"$OUTFILE"
        echo "" >>"$OUTFILE"
        LogMessage "Encrypting session key..." 2
        echo "K.....,_" >>"$OUTFILE"
        echo -n "$SESSION_KEY" | openssl rsautl -encrypt -pubin -inkey $PUBKEY -oaep >>"$OUTFILE" || {
            LogMessage "Fatal: Can't encrypt session key"
            DELETE_OUTFILE="1"
            exit 3
        }
        echo "" >>"$OUTFILE"
        if [ "$SIGN" ]; then
            if [ "$PRIVKEY" ]; then
                LogMessage "Signing data..."
                SIGNATURE=`openssl sha512 -sign "$PRIVKEY" -binary "$INFILE" || echo ""`
                if [ "$SIGNATURE" ]; then
                    echo "S.....,_" >>"$OUTFILE"
                    echo "$SIGNATURE" >>"$OUTFILE"
                else
                    LogMessage "Warning: Can't sign the data" 1
                    LogMessage "Continue without signature" 2
                fi
            else
                LogMessage "Warning: Can't sign the data without proper private key." 1
            fi
        fi
    fi
    LogMessage "Data encrypted successfully"
elif [ "$MODE" = "dec" ]; then
    HEAD=`head -n 1 "$INFILE"`
    if echo "$HEAD" | grep -- '-----BEGIN' >/dev/null 2>&1; then
        if [ -z "$ARMOR" ]; then
        # something's wrong: command line option
        # doesn't correspond to input file format
            LogMessage "Actual file format is ASCII armored." 1
            LogMessage "Using 'armor' parser" 2
            ARMOR="1"
        fi
    elif echo "$HEAD" | grep '.....,_' >/dev/null 2>&1; then
        if [ "$ARMOR" ]; then
        # something's wrong: command line option
        # doesn't correspond to input file format
            LogMessage "Actual file format is binary." 1
            LogMessage "Using 'binary' parser" 2
            ARMOR=""
        fi
    else
        LogMessage "Unknown input file format"
        exit 5
    fi
    GetPrivateKey
    [ "$NEW_PRIV_KEY" ] && {
        PRIVKEY=$NEW_PRIV_KEY
        AGE="new "
    } || {
        AGE="original "
    }
    LogMessage "Using $AGE$PRIVKEY for decryption." 3
    SIGNATURE=""
    if [ "$ARMOR" ]; then
        sed -e '/^$/d' $INFILE | csplit --suppress-matched -s -z - '/-----END/' '{*}'
    else
        csplit -s -z "$INFILE" '/.....,_/' '{*}'
    fi
    DIRTY="1"
    LogMessage "Parsing input file..."
    for PART in xx*; do
        if [ "$ARMOR" ]; then
            HEAD=`head -n 1 "$PART"`
            TYPE=`echo "$HEAD" | cut -d ' ' -f 2`
            case "$TYPE" in
                ENCRYPTED)
                    [ -z "$OUTFILE" ] && {
                        ENCODED_NAME=`echo "$HEAD" | sed -e 's/.*: \(.\+\)-----$/\1/' | base64 -d`
                    }
                    DATAFILE=`tempfile -d . -p data- -s .bin`
                    sed -i -e '/-----/d' "$PART"
                    base64 -d "$PART" > "$DATAFILE"
                    DIRTY="1"
                    ;;
                SESSION)
                    SESSION_KEY=`sed -e '/-----/d' $PART | base64 -d | openssl rsautl -decrypt -inkey $PRIVKEY -oaep` || {
                        LogMessage "Fatal: Can't decrypt session key."
                        exit 3
                    }
                    ;;
                DIGITAL)
                    SIGNATURE=`tempfile -d . -p sign- -s .bin`
                    sed -i -e '/-----/d' "$PART"
                    base64 -d "$PART" > "$SIGNATURE"
                    DIRTY="1"
                    ;;
                *)
                    ;;
            esac
        else
            TYPE=`head -c 1 "$PART"`
            sed -i -e '/.....,_/d' $PART
            # dirty hack: remove last "\n" before EOF
            truncate -s $(($(stat -c '%s' $PART)-1)) $PART
            # another way:
            # perl -pi -e 'chomp if eof' file
            # or
            # head -c -1 file > another_file
            case "$TYPE" in
                N)
                    [ -z "$OUTFILE" ] && {
                        ENCODED_NAME=`cat $PART`
                    }
                    ;;
                D)
                    DATAFILE=`tempfile -d . -p data- -s .bin`
                    cat "$PART" >"$DATAFILE"
                    DIRTY="1"
                    ;;
                K)
                    SESSION_KEY=`cat $PART | openssl rsautl -decrypt -inkey $PRIVKEY -oaep` || {
                        LogMessage "Fatal: Can't decrypt session key."
                        exit 3
                    }
                    ;;
                S)
                    SIGNATURE=`tempfile -d . -p sign- -s .bin`
                    cat "$PART" > "$SIGNATURE"
                    DIRTY="1"
                    ;;
                *)
                    ;;
            esac
        fi
    done
    LogMessage "Checking outfile" 2
    [ -z "$OUTFILE" ] && {
        LogMessage "No parameter for outfile. Trying to decrypt original name." 1
        export SESSION_KEY
        OUTFILE=`echo -n $ENCODED_NAME | openssl aes-256-ofb -d -nosalt -pass env:SESSION_KEY || echo ""`
        [ -z "$OUTFILE" ] && OUTFILE="$INFILE.decrypted"
        [ -f "$OUTFILE" ] && {
            LogMessage "File $OUTFILE already exists." 2
            OUTFILE="$OUTFILE.decrypted"
        }
        LogMessage "Setting outfile name to $OUTFILE" 1
    }
    LogMessage "Decrypting..."
    COMPRESSED="$OUTFILE.gz"
    openssl aes-256-ofb -d -pass env:SESSION_KEY -in "$DATAFILE" -out "$COMPRESSED" || {
        LogMessage "Fatal: Can't decrypt data."
        exit 5
    }
    gzip -d -f "$COMPRESSED"
    if [ "$SIGNATURE" ]; then
        LogMessage "Verifying..."
        if GetPublicKey; then
            [ "$NEW_PUB_KEY" ] && PUBKEY=$NEW_PUB_KEY
            openssl sha512 -verify "$PUBKEY" -signature "$SIGNATURE" "$OUTFILE" || {
                LogMessage "Warning: Can't check signature!"
            }
        else
            LogMessage "Warning: Data authenticity can't be verified." 1
        fi
    fi
    LogMessage "Data decrypted successfully"
else
    LogMessage "I don't know what to do. Sorry." 1
    LogMessage "Try to use '--enc' or '--dec' options."
    exit 10
fi

exit 0
