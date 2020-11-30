#!/bin/bash
#
# Regards, the Alveare Solutions society.
#
declare -A MACHINE_FINGERPRINT_PATTERNS
declare -A DEFAULT
declare -A CHECKSUM_ALGORITHMS
declare -A ISEEYOU_FINGERPRINT_VALUES
declare -A ISEEYOU_FINGERPRINT_CACHE

declare -a LOGGING_LEVELS
declare -a MACHINE_FINGERPRINTS

CONF_FILE_PATH="$1"

if [ -f "$CONF_FILE_PATH" ]; then
    source $CONF_FILE_PATH
fi

ISEEYOU_FINGERPRINT_VALUES=(
['processor-part-number']='fetch_fingerprint_processor_part_number'
['processor-serial']='fetch_fingerprint_processor_serial'
['processor-manufacturer']='fetch_fingerprint_processor_manufacturer'
['processor-core-count']='fetch_fingerprint_processor_core_count'
['processor-type']='fetch_fingerprint_processor_type'
['processor-id']='fetch_fingerprint_processor_id'
['memory-part-number']='fetch_fingerprint_memory_part_number'
['memory-serial']='fetch_fingerprint_memory_serial'
['memory-manufacturer']='fetch_fingerprint_memory_manufacturer'
['memory-size']='fetch_fingerprint_memory_size'
['chassis-manufacturer']='fetch_fingerprint_chassis_manufacturer'
['chassis-type']='fetch_fingerprint_chassis_type'
['chassis-version']='fetch_fingerprint_chassis_version'
['chassis-serial']='fetch_fingerprint_chassis_serial'
['chassis-sku']='fetch_fingerprint_chassis_sku'
['product-name']='fetch_fingerprint_product_name'
['product-manufacturer']='fetch_fingerprint_product_manufacturer'
['product-serial']='fetch_fingerprint_product_serial'
['product-uuid']='fetch_fingerprint_product_uuid'
['product-sku']='fetch_fingerprint_product_sku'
['product-version']='fetch_fingerprint_product_version'
['product-baseboard']='fetch_fingerprint_product_baseboard'
['bios-vendor']='fetch_fingerprint_bios_vendor'
['bios-version']='fetch_fingerprint_bios_version'
['baseboard-manufacturer']='fetch_fingerprint_baseboard_manufacturer'
['baseboard-version']='fetch_fingerprint_baseboard_version'
['baseboard-serial']='fetch_fingerprint_baseboard_serial'
['baseboard-type']='fetch_fingerprint_baseboard_type'
)

# FETCHERS

function fetch_machine_fingerprint_resources () {
    if [ ${#MACHINE_FINGERPRINTS[@]} -eq 0 ]; then
        echo; error_msg "No machine fingerprint resources found."
        return 1
    fi
    echo ${MACHINE_FINGERPRINTS[@]}
    return 0
}

function fetch_machine_fingerprint_value () {
    local FINGERPRINT_RESOURCE="$1"
    check_valid_fingerprint_resource "$FINGERPRINT_RESOURCE"
    if [ $? -ne 0 ]; then
        echo; error_msg "# Invalid machine fingerprint resource"\
            "${RED}$FINGERPRINT_RESOURCE${RESET}."
        return 1
    fi
    debug_msg "Fingerprint cache (${!ISEEYOU_FINGERPRINT_CACHE[@]})."
    if [ ! -z "${ISEEYOU_FINGERPRINT_CACHE[$FINGERPRINT_RESOURCE]}" ]; then
        debug_msg "Fetched fingerprint resource ($FINGERPRINT_RESOURCE)"\
            "from cache - ${ISEEYOU_FINGERPRINT_CACHE[$FINGERPRINT_RESOURCE]}"
        echo "${ISEEYOU_FINGERPRINT_CACHE[$FINGERPRINT_RESOURCE]}"
        return $?
    fi
    RESOURCE_VALUE=`${ISEEYOU_FINGERPRINT_VALUES[$FINGERPRINT_RESOURCE]}`
    echo "$RESOURCE_VALUE"
    return 0
}

function fetch_fingerprint_baseboard_type () {
    BASEBOARD_DATA=`fetch_all_baseboard_data`
    BASEBOARD_TYPE=`filter_fingerprint_type "$BASEBOARD_DATA" | sort -u`
    debug_msg "Detected baseboard type ($BASEBOARD_TYPE)."
    convert_array_to_delimited_string ',' ${BASEBOARD_TYPE[@]}
    return 0
}

function fetch_fingerprint_processor_part_number () {
    PROCESSOR_DATA=`fetch_all_processor_data`
    PROCESSOR_PART_NUMBER=`filter_fingerprint_part_number "$PROCESSOR_DATA" | sort -u`
    debug_msg "Detected processor part number (${PROCESSOR_PART_NUMBER[@]})."
    convert_array_to_delimited_string ',' "${PROCESSOR_PART_NUMBER[@]}"
    return 0
}

function fetch_fingerprint_processor_serial () {
    PROCESSOR_DATA=`fetch_all_processor_data`
    PROCESSOR_SERIAL_NUMBER=`filter_fingerprint_serial_number "$PROCESSOR_DATA" | sort -u`
    debug_msg "Detected processor serial number (${PROCESSOR_SERIAL_NUMBER[@]})."
    convert_array_to_delimited_string ',' "${PROCESSOR_SERIAL_NUMBER[@]}"
    return 0
}

function fetch_fingerprint_processor_manufacturer () {
    PROCESSOR_DATA=`fetch_all_processor_data`
    PROCESSOR_MANUFACTURER=`filter_fingerprint_manufacturer "$PROCESSOR_DATA" | sort -u`
    debug_msg "Detected processor manufacturer (${PROCESSOR_MANUFACTURER[@]})."
    echo "${PROCESSOR_MANUFACTURER[@]}"
    return 0
}

function fetch_fingerprint_processor_core_count () {
    PROCESSOR_DATA=`fetch_all_processor_data`
    PROCESSOR_CORE_COUNT=`filter_fingerprint_core_count "$PROCESSOR_DATA"`
    debug_msg "Detected processor core count (${PROCESSOR_CORE_COUNT[@]})."
    convert_array_to_delimited_string ',' "${PROCESSOR_CORE_COUNT[@]}"
    return 0
}

function fetch_fingerprint_processor_type () {
    PROCESSOR_DATA=`fetch_all_processor_data`
    PROCESSOR_TYPE=`filter_fingerprint_type "$PROCESSOR_DATA" | sort -u`
    debug_msg "Detected processor type (${PROCESSOR_TYPE[@]})."
    convert_array_to_delimited_string ',' "${PROCESSOR_TYPE[@]}"
    return 0
}

function fetch_fingerprint_processor_id () {
    PROCESSOR_DATA=`fetch_all_processor_data`
    PROCESSOR_ID=`filter_fingerprint_id "$PROCESSOR_DATA" | sort -u`
    debug_msg "Detected processor ID (${PROCESSOR_ID[@]})."
    convert_array_to_delimited_string ',' "${PROCESSOR_ID[@]}"
    return 0
}

function fetch_fingerprint_memory_part_number () {
    MEMORY_DATA=`fetch_all_memory_data`
    MEMORY_PART_NUMEBER=`filter_fingerprint_part_number "$MEMORY_DATA" | sort -u`
    debug_msg "Detected memory part number (${MEMORY_PART_NUMEBER[@]})."
    convert_array_to_delimited_string ',' "${MEMORY_PART_NUMEBER[@]}"
    return 0
}

function fetch_fingerprint_memory_serial () {
    MEMORY_DATA=`fetch_all_memory_data`
    MEMORY_SERIAL_NUMEBER=`filter_fingerprint_serial_number "$MEMORY_DATA" | sort -u`
    debug_msg "Detected memory serial number (${MEMORY_SERIAL_NUMEBER[@]})."
    convert_array_to_delimited_string ',' "${MEMORY_SERIAL_NUMEBER[@]}"
    return 0
}

function fetch_fingerprint_memory_manufacturer () {
    MEMORY_DATA=`fetch_all_memory_data`
    MEMORY_MANUFACTURER=`filter_fingerprint_manufacturer "$MEMORY_DATA" | sort -u`
    debug_msg "Detected memory manufacturer (${MEMORY_MANUFACTURER[@]})."
    convert_array_to_delimited_string ',' "${MEMORY_MANUFACTURER[@]}"
    return 0
}

function fetch_fingerprint_memory_size () {
    MEMORY_DATA=`fetch_all_memory_data`
    MEMORY_SIZE=`filter_fingerprint_size "$MEMORY_DATA" | awk '{print $1$2}' | sort -u`
    debug_msg "Detected memory size (${MEMORY_SIZE[@]})."
    convert_array_to_delimited_string ',' "${MEMORY_SIZE[@]}"
    return 0
}

function fetch_fingerprint_chassis_manufacturer () {
    CHASSIS_DATA=`fetch_all_chassis_data`
    CHASSIS_MANUFACTURER=`filter_fingerprint_manufacturer "$CHASSIS_DATA" | sort -u`
    debug_msg "Detected chassis manufacturer (${CHASSIS_MANUFACTURER[@]})."
    convert_array_to_delimited_string ',' "${CHASSIS_MANUFACTURER[@]}"
    return 0
}

function fetch_fingerprint_chassis_type () {
    CHASSIS_DATA=`fetch_all_chassis_data`
    CHASSIS_TYPE=`filter_fingerprint_type "$CHASSIS_DATA" | sort -u`
    debug_msg "Detected chassis type (${CHASSIS_TYPE[@]})."
    convert_array_to_delimited_string ',' "${CHASSIS_TYPE[@]}"
    return 0
}

function fetch_fingerprint_chassis_version () {
    CHASSIS_DATA=`fetch_all_chassis_data`
    CHASSIS_VERSION=`filter_fingerprint_version "$CHASSIS_DATA"`
    debug_msg "Detected chassis version (${CHASSIS_VERSION[@]})."
    convert_array_to_delimited_string ',' "${CHASSIS_VERSION[@]}"
    return 0
}

function fetch_fingerprint_chassis_serial () {
    CHASSIS_DATA=`fetch_all_chassis_data`
    CHASSIS_SERIAL_NUMBER=`filter_fingerprint_serial_number "$CHASSIS_DATA" | sort -u`
    debug_msg "Detected chassis serial number (${CHASSIS_SERIAL_NUMBER[@]})."
    convert_array_to_delimited_string ',' "${CHASSIS_SERIAL_NUMBER[@]}"
    return 0
}

function fetch_fingerprint_chassis_sku () {
    CHASSIS_DATA=`fetch_all_chassis_data`
    CHASSIS_SKU=`filter_fingerprint_stock_keeping_unit "$CHASSIS_DATA" | sort -u`
    debug_msg "Detected chassis stock keeping unit (${CHASSIS_SKU[@]})."
    convert_array_to_delimited_string ',' "${CHASSIS_SKU[@]}"
    return 0
}

function fetch_fingerprint_product_name () {
    SYSTEM_DATA=`fetch_all_system_data`
    PRODUCT_NAME=`filter_fingerprint_name "$SYSTEM_DATA" | sort -u`
    debug_msg "Detected product name (${PRODUCT_NAME[@]})."
    convert_array_to_delimited_string ',' "${PRODUCT_NAME[@]}"
    return 0
}

function fetch_fingerprint_product_manufacturer () {
    SYSTEM_DATA=`fetch_all_system_data`
    PRODUCT_MANUFACTURER=`filter_fingerprint_manufacturer "$SYSTEM_DATA" | sort -u`
    debug_msg "Detected product manufacturer (${PRODUCT_MANUFACTURER[@]})."
    convert_array_to_delimited_string ',' "${PRODUCT_MANUFACTURER[@]}"
    return 0
}

function fetch_fingerprint_product_serial () {
    SYSTEM_DATA=`fetch_all_system_data`
    PRODUCT_SERIAL_NUMBER=`filter_fingerprint_serial_number "$SYSTEM_DATA" | sort -u`
    debug_msg "Detected product manufacturer (${PRODUCT_SERIAL_NUMBER[@]})."
    convert_array_to_delimited_string ',' "${PRODUCT_SERIAL_NUMBER[@]}"
    return 0
}

function fetch_fingerprint_product_uuid () {
    SYSTEM_DATA=`fetch_all_system_data`
    PRODUCT_UUID=`filter_fingerprint_universally_unique_identifier "$SYSTEM_DATA" | sort -u`
    debug_msg "Detected product UUID (${PRODUCT_UUID[@]})."
    convert_array_to_delimited_string ',' "${PRODUCT_UUID[@]}"
    return 0
}

function fetch_fingerprint_product_sku () {
    SYSTEM_DATA=`fetch_all_system_data`
    PRODUCT_SKU=`filter_fingerprint_stock_keeping_unit "$SYSTEM_DATA" | sort -u`
    debug_msg "Detected product SKU (${PRODUCT_SKU[@]})."
    convert_array_to_delimited_string ',' "${PRODUCT_SKU[@]}"
    return 0
}

function fetch_fingerprint_product_version () {
    SYSTEM_DATA=`fetch_all_system_data`
    PRODUCT_VERSION=`filter_fingerprint_version "$SYSTEM_DATA"`
    debug_msg "Detected product version (${PRODUCT_VERSION[@]})."
    convert_array_to_delimited_string ',' "${PRODUCT_VERSION[@]}"
    return 0
}

function fetch_fingerprint_product_baseboard () {
    BASEBOARD_DATA=`fetch_all_baseboard_data`
    BASEBOARD_PRODUCT_NAME=`filter_fingerprint_product "$BASEBOARD_DATA" | sort -u`
    debug_msg "Detected baseboard product name (${BASEBOARD_PRODUCT_NAME[@]})."
    convert_array_to_delimited_string ',' "${BASEBOARD_PRODUCT_NAME[@]}"
    return 0
}

function fetch_fingerprint_bios_vendor () {
    BIOS_DATA=`fetch_all_bios_data`
    BIOS_VENDOR=`filter_fingerprint_vendor "$BIOS_DATA" | sort -u`
    debug_msg "Detected bios vendor (${BIOS_VENDOR[@]})."
    convert_array_to_delimited_string ',' "${BIOS_VENDOR[@]}"
    return 0
}

function fetch_fingerprint_bios_version () {
    BIOS_DATA=`fetch_all_bios_data`
    BIOS_VERSION=`filter_fingerprint_version "$BIOS_DATA"`
    debug_msg "Detected bios version (${BIOS_VERSION[@]})."
    convert_array_to_delimited_string ',' "${BIOS_VERSION[@]}"
    return 0
}

function fetch_fingerprint_baseboard_manufacturer () {
    BASEBOARD_DATA=`fetch_all_baseboard_data`
    BASEBOARD_MANUFACTURER=`filter_fingerprint_manufacturer "$BASEBOARD_DATA" | sort -u`
    debug_msg "Detected baseboard manufacturer (${BASEBOARD_MANUFACTURER[@]})."
    convert_array_to_delimited_string ',' "${BASEBOARD_MANUFACTURER[@]}"
    return 0
}

function fetch_fingerprint_baseboard_version () {
    BASEBOARD_DATA=`fetch_all_baseboard_data`
    BASEBOARD_VERSION=`filter_fingerprint_version "$BASEBOARD_DATA"`
    debug_msg "Detected baseboard version (${BASEBOARD_VERSION[@]})."
    convert_array_to_delimited_string ',' "${BASEBOARD_VERSION[@]}"
    return 0
}

function fetch_fingerprint_baseboard_serial () {
    BASEBOARD_DATA=`fetch_all_baseboard_data`
    BASEBOARD_SERIAL_NUMBER=`filter_fingerprint_serial_number "$BASEBOARD_DATA" | sort -u`
    debug_msg "Detected baseboard serial number (${BASEBOARD_SERIAL_NUMBER[@]})."
    convert_array_to_delimited_string ',' "${BASEBOARD_SERIAL_NUMBER[@]}"
    return 0
}

function fetch_machine_fingerprint_pattern_labels () {
    if [ ${#MACHINE_FINGERPRINT_PATTERNS[@]} -eq 0 ]; then
        error_msg "No machine fingerprint patterns found."
        return 1
    fi
    echo ${!MACHINE_FINGERPRINT_PATTERNS[@]}
    return 0
}

function fetch_machine_fingerprint_pattern_by_label () {
    local PATTERN_LABEL="$1"
    check_valid_machine_fingerprint_pattern_label "$PATTERN_LABEL"
    if [ $? -ne 0 ]; then
        error_msg "Invalid machine fingerprint pattern label"\
            "${RED}$PATTERN_LABEL${RESET}."
        return 1
    fi
    echo ${MACHINE_FINGERPRINT_PATTERNS[$PATTERN_LABEL]}
    return 0
}

function fetch_all_bios_data () {
    dmidecode -t bios
    return $?
}

function fetch_all_system_data () {
    dmidecode -t system
    return $?
}

function fetch_all_baseboard_data () {
    dmidecode -t baseboard
    return $?
}

function fetch_all_chassis_data () {
    dmidecode -t chassis
    return $?
}

function fetch_all_processor_data () {
    dmidecode -t processor
    return $?
}

function fetch_all_memory_data () {
    dmidecode -t memory
    return $?
}

function fetch_checksum_algorithm_labels () {
    if [ ${#CHECKSUM_ALGORITHMS[@]} -eq 0 ]; then
        echo; error_msg "No ${BLUE}$SCRIPT_NAME${RESET}"\
            "${RED}checksum algorithms${RESET} found."
        return 1
    fi
    echo ${!CHECKSUM_ALGORITHMS[@]}
    return 0
}

function fetch_checksum_command_by_label () {
    local LABEL="$1"
    check_valid_checksum_label "$LABEL"
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid checksum algorithm label"\
            "${RED}$LABEL${RESET}."
        return 1
    fi
    echo ${CHECKSUM_ALGORITHMS[$LABEL]}
    return 0
}

function fetch_set_log_levels () {
    if [ ${#LOGGING_LEVELS[@]} -eq 0 ]; then
        echo; error_msg "No ${BLUE}$SCRIPT_NAME${RESET}"\
            "${RED}logging levels${RESET} found."
        return 1
    fi
    echo ${LOGGING_LEVELS[@]}
    return 0
}

function fetch_data_from_user () {
    local PROMPT="$1"
    local OPTIONAL="${@:2}"
    while :
    do
        if [[ $OPTIONAL == 'password' ]]; then
            read -sp "$PROMPT: " DATA
        else
            read -p "$PROMPT> " DATA
        fi
        if [ -z "$DATA" ]; then
            continue
        elif [[ "$DATA" == ".back" ]]; then
            return 1
        fi
        echo "$DATA"; break
    done
    return 0
}

function fetch_ultimatum_from_user () {
    PROMPT="$1"
    while :
    do
        local ANSWER=`fetch_data_from_user "$PROMPT"`
        case "$ANSWER" in
            'y' | 'Y' | 'yes' | 'Yes' | 'YES')
                return 0
                ;;
            'n' | 'N' | 'no' | 'No' | 'NO')
                return 1
                ;;
            *)
        esac
    done
    return 2
}

function fetch_selection_from_user () {
    local PROMPT="$1"
    local OPTIONS=( "${@:2}" "Back" )
    local OLD_PS3=$PS3
    PS3="$PROMPT> "
    select opt in "${OPTIONS[@]}"; do
        case "$opt" in
            'Back')
                PS3="$OLD_PS3"
                return 1
                ;;
            *)
                local CHECK=`check_item_in_set "$opt" "${OPTIONS[@]}"`
                if [ $? -ne 0 ]; then
                    warning_msg "Invalid option."
                    continue
                fi
                PS3="$OLD_PS3"
                echo "$opt"
                return 0
                ;;
        esac
    done
    PS3="$OLD_PS3"
    return 1
}

# SETTERS

function set_log_line_count () {
    local LINE_COUNT=$1
    check_value_is_number $LINE_COUNT
    if [ $? -ne 0 ]; then
        echo; error_msg "Value ${RED}$LINE_COUNT${RESET}"\
            "is not a number."
        return 1
    fi
    DEFAULT['log-lines']=$LINE_COUNT
    return 0
}

function set_log_file () {
    local FILE_PATH="$1"
    check_file_exists "$FILE_PATH"
    if [ $? -ne 0 ]; then
        echo; error_msg "File ${RED}$FILE_PATH${RESET} not found."
        return 1
    fi
    DEFAULT['log-file']="$FILE_PATH"
    return 0
}

function set_fingerprint_pattern () {
    local PATTERN_LABEL="$1"
    local FINGERPRINT_PATTERN="$2"
    if [ ! -z "${MACHINE_FINGERPRINT_PATTERNS[$PATTERN_LABEL]}" ]; then
        warning_msg "Machine finger print pattern"\
            "${RED}$PATTERN_LABEL${RESET} already exists."
        return 1
    fi
    MACHINE_FINGERPRINT_PATTERNS[$PATTERN_LABEL]="$FINGERPRINT_PATTERN"
    return 0
}

function set_iseeyou_fingerprint_pattern () {
    local FINGERPRINT_PATTERN_LABEL="$1"
    VALID_FINGERPRINT_PATTERNS=( `fetch_machine_fingerprint_pattern_labels` )
    check_item_in_set "$FINGERPRINT_PATTERN_LABEL" ${VALID_FINGERPRINT_PATTERNS[@]}
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid machine fingerprint pattern"\
            "${RED}$FINGERPRINT_PATTERN_LABEL${RESET}."
        return 1
    fi
    ISEEYOU_FINGERPRINT="$FINGERPRINT_PATTERN_LABEL"
    return 0
}

function set_checksum_algorithm () {
    local ALGORITHM="$1"
    VALID_HASHING_ALGORITHMS=( `fetch_checksum_algorithm_labels` )
    check_item_in_set "$ALGORITHM" ${VALID_HASHING_ALGORITHMS[@]}
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid checksum hashing algorithm ${RED}$ALGORITHM${RESET}."
        return 1
    fi
    ISEEYOU_CHECKSUM="$ALGORITHM"
    return 0
}

function set_temporary_file () {
    local FILE_PATH="$1"
    check_file_exists "$FILE_PATH"
    if [ $? -ne 0 ]; then
        echo; error_msg "File ${RED}$FILE_PATH${RESET} not found."
        return 1
    fi
    DEFAULT['tmp-file']="$FILE_PATH"
    return 0
}

function set_iseeyou_logging () {
    local LOGGING="$1"
    if [[ "$LOGGING" != 'on' ]] && [[ "$LOGGING" != 'off' ]]; then
        echo; error_msg "Invalid logging value ${RED}$LOGGING${RESET}."\
            "Defaulting to ${GREEN}ON${RESET}."
        ISEEYOU_LOGGING='on'
        return 1
    fi
    ISEEYOU_LOGGING="$LOGGING"
    return 0
}

# CHECKERS

function check_valid_fingerprint_pattern () {
    local PATTERN="$1"
    FINGERPRINT_PATTERN=( `echo "$PATTERN" | tr ',' ' '` )
    for resource in "${FINGERPRINT_PATTERN[@]}"; do
        check_valid_fingerprint_resource "$resource"
        if [ $? -ne 0 ]; then
            return 1
        fi
    done
    return 0
}

function check_file_has_number_of_lines () {
    local FILE_PATH="$1"
    local FILE_LINES=$2
    check_value_is_number $FILE_LINES
    if [ $? -ne 0 ]; then
        error_msg "Invalid value for file line number"\
            "${RED}$FILE_LINES${RESET}."
        return 2
    fi
    check_file_exists "$FILE_PATH"
    if [ $? -ne 0 ]; then
        error_msg "File ${RED}$FILE_PATH${RESET} does not exist."
        return 3
    fi
    LINE_COUNT=`cat "$FILE_PATH" | wc -l`
    if [ $? -ne 0 ]; then
        warning_msg "Could not find out how many lines there are in file"\
            "${RED}$FILE_PATH${RESET}."
        return 4
    elif [ $LINE_COUNT -eq $FILE_LINES ]; then
        return 0
    fi
    return 1
}

function check_valid_fingerprint_resource () {
    local FINGERPRINT_RESOURCE="$1"
    VALID_FINGERPRINT_RESOURCES=( `fetch_machine_fingerprint_resources` )
    check_item_in_set "$FINGERPRINT_RESOURCE" ${VALID_FINGERPRINT_RESOURCES[@]}
    return $?
}

function check_preview_on () {
    if [[ "$ISEEYOU_PREVIEW" != 'on' ]]; then
        return 1
    fi
    return 0
}

function check_preview_off () {
    if [[ "$ISEEYOU_PREVIEW" != 'off' ]]; then
        return 1
    fi
    return 0
}

function check_logging_on () {
    if [[ "$ISEEYOU_LOGGING" != 'on' ]]; then
        return 1
    fi
    return 0
}

function check_logging_off () {
    if [[ "$ISEEYOU_LOGGING" != 'off' ]]; then
        return 1
    fi
    return 0
}

function check_valid_machine_fingerprint_pattern_label () {
    local PATTERN_LABEL="$1"
    VALID_FINGERPRINT_PATTERNS=( `fetch_machine_fingerprint_pattern_labels` )
    check_item_in_set "$PATTERN_LABEL" ${VALID_FINGERPRINT_PATTERNS[@]}
    return $?
}

function check_valid_checksum_label () {
    local LABEL="$1"
    VALID_LABELS=( `fetch_checksum_algorithm_labels` )
    check_item_in_set "$LABEL" ${VALID_LABELS[@]}
    return $?
}

function check_value_is_number () {
    local VALUE=$1
    test $VALUE -eq $VALUE &> /dev/null
    return $?
}

function check_checksum_is_valid () {
    local CHECKSUM="$1"
    local CHECKSUM_LENGTH_MAX="$2"
    local REGEX="$3"
    if [ -z "$CHECKSUM" ]; then
        echo; error_msg "No checksum specified."
        echo; return 3
    elif [ -z "$CHECKSUM_LENGTH_MAX" ]; then
        echo; error_msg "No maximum checksum length specified."
        echo; return 4
    elif [ -z "$REGEX" ]; then
        echo; error_msg "No checksum regex pattern specified."
        echo; return 5
    fi
    echo "$CHECKSUM" | egrep -e $REGEX &> /dev/null
    if [ $? -ne 0 ]; then
        debug_msg "Given checksum value $CHECKSUM does not corespond to"\
            "REGEX pattern $REGEX."
        return 1
    fi
    CHECKSUM_LENGTH=`echo "$CHECKSUM" | wc -c`
    debug_msg "Detected checksum length ($CHECKSUM_LENGTH)."
    CHECKSUM_LENGTH_MIN=$((CHECKSUM_LENGTH_MAX - 6))
    debug_msg "Computed error margin checksum length"\
        "floor value ($CHECKSUM_LENGTH_MIN characters)."
    if [ $CHECKSUM_LENGTH -le $CHECKSUM_LENGTH_MIN ] \
            || [ $CHECKSUM_LENGTH -gt $CHECKSUM_LENGTH_MAX ]; then
        debug_msg "Given checksum value ($CHECKSUM) does not corespond to"\
            "valid ($ISEEYOU_CHECKSUM) hash length range"\
            "($CHECKSUM_LENGTH_MIN - $CHECKSUM_LENGTH_MAX characters)."
        return 2
    fi
    return 0
}

function check_valid_md5_checksum () {
    local CHECKSUM="$1"
    check_checksum_is_valid "$CHECKSUM" 36 '[a-zA-Z0-9]'
    return $?
}

function check_valid_sha1_checksum () {
    local CHECKSUM="$1"
    check_checksum_is_valid "$CHECKSUM" 44 '[a-zA-Z0-9]'
    return $?
}

function check_valid_sha256_checksum () {
    local CHECKSUM="$1"
    check_checksum_is_valid "$CHECKSUM" 68 '[a-zA-Z0-9]'
    return $?
}

function check_valid_sha512_checksum () {
    local CHECKSUM="$1"
    check_checksum_is_valid "$CHECKSUM" 132 '[a-zA-Z0-9]'
    return $?
}

function check_valid_checksum () {
    local CHECKSUM="$1"
    if [ -z "$ISEEYOU_CHECKSUM" ]; then
        echo; error_msg "${BLUE}$SCRIPT_NAME${RESET} checksum"\
            "hashing algorithm not set."
        echo; return 1
    fi
    debug_msg "Detected $SCRIPT_NAME default checksum set to $ISEEYOU_CHECKSUM."
    SANITIZED_CHECKSUM=`echo "$CHECKSUM" | sed -e 's/ //g' -e 's/-//g'`
    debug_msg "Original checksum $CHECKSUM sanitized to $SANITIZED_CHECKSUM."
    case "$ISEEYOU_CHECKSUM" in
        'MD5')
            check_valid_md5_checksum "$CHECKSUM"
            ;;
        'SHA1')
            check_valid_sha1_checksum "$CHECKSUM"
            ;;
        'SHA256')
            check_valid_sha256_checksum "$CHECKSUM"
            ;;
        'SHA512')
            check_valid_sha512_checksum "$CHECKSUM"
            ;;
        *)
            echo; error_msg "Invalid ${BLUE}$SCRIPT_NAME${RESET} checksum"\
                "algorithm set. Defaulting to ${CYAN}MD5${RESET}."
            set_checksum_algorithm "MD5"
            echo; return 2
            ;;
    esac
    return $?
}

function check_file_empty () {
    local FILE_PATH="$1"
    if [ ! -s "$FILE_PATH" ]; then
        return 0
    fi
    return 1
}

function check_directory_empty () {
    local DIR_PATH="$1"
    FILE_COUNT=`ls -a1 "$DIR_PATH" | grep -v '^.$' | grep -v '^..$' | wc -l`
    if [ $FILE_COUNT -eq 0 ]; then
        return 0
    fi
    return 1
}

function check_loglevel_set () {
    local LOG_LEVEL="$1"
    LOG_LEVELS=( `fetch_set_log_levels` )
    if [ $? -ne 0 ]; then
        return 1
    fi
    check_item_in_set "$LOG_LEVEL" ${LOG_LEVELS[@]}
    return $?
}

function check_identical_strings () {
    local FIRST_STRING="$1"
    local SECOND_STRING="$2"
    if [[ "$FIRST_STRING" != "$SECOND_STRING" ]]; then
        return 1
    fi
    return 0
}

function check_file_exists () {
    local FILE_PATH="$1"
    if [ -f "$FILE_PATH" ]; then
        return 0
    fi
    return 1
}

function check_directory_exists () {
    local DIR_PATH="$1"
    if [ -d "$DIR_PATH" ]; then
        return 0
    fi
    return 1
}

function check_privileged_access () {
    if [ $EUID -ne 0 ]; then
        return 1
    fi
    return 0
}

function check_item_in_set () {
    local ITEM="$1"
    ITEM_SET=( "${@:2}" )
    for SET_ITEM in "${ITEM_SET[@]}"; do
        if [[ "$ITEM" == "$SET_ITEM" ]]; then
            return 0
        fi
    done
    return 1
}

function check_util_installed () {
    local UTIL_NAME="$1"
    type "$UTIL_NAME" &> /dev/null && return 0 || return 1
}

# INSTALLERS

function apt_install_dependency() {
    local UTIL="$1"
    symbol_msg "${GREEN}+${RESET}" \
        "Installing package ${YELLOW}$UTIL${RESET}..."
    apt-get install $UTIL
    return $?
}

function apt_install_full_clip_logic_sniper_dependencies () {
    if [ ${#APT_DEPENDENCIES[@]} -eq 0 ]; then
        info_msg 'No dependencies to fetch using the apt package manager.'
        return 1
    fi
    local FAILURE_COUNT=0
    echo; info_msg "Installing dependencies using apt package manager:"
    for package in "${APT_DEPENDENCIES[@]}"; do
        check_util_installed "$package"
        if [ $? -eq 0 ]; then
            ok_msg "${BLUE}$SCRIPT_NAME${RESET} dependency"\
                "${GREEN}$package${RESET} already is installed."
            continue
        fi
        echo; apt_install_dependency $package
        if [ $? -ne 0 ]; then
            nok_msg "Failed to install ${YELLOW}$SCRIPT_NAME${RESET}"\
                "dependency ${RED}$package${RESET}!"
            FAILURE_COUNT=$((FAILURE_COUNT + 1))
        else
            ok_msg "Successfully installed ${YELLOW}$SCRIPT_NAME${RESET}"\
                "dependency ${GREEN}$package${RESET}."
            INSTALL_COUNT=$((INSTALL_COUNT + 1))
        fi
    done
    if [ $FAILURE_COUNT -ne 0 ]; then
        echo; warning_msg "${RED}$FAILURE_COUNT${RESET} dependency"\
            "installation failures!"\
            "Try installing the packages manually ${GREEN}:)${RESET}"
    fi
    return 0
}

# FILTERS

function filter_fingerprint_records () {
    FINGERPRINT_RECORDS=( $@ )
    VALID_FINGERPRINT_RECORDS=()
    INVALID_FINGERPRINT_RECORDS=(
        'BADINDEX'
        'Unknown'
    )
    debug_msg "(${FINGERPRINT_RECORDS[@]}) - (${INVALID_FINGERPRINT_RECORDS[@]})"
    for record in "${FINGERPRINT_RECORDS[@]}"; do
        SANITIZED_RECORD=`echo "$record" | \
            sed -e 's/<//g' -e 's/>//g' -e 's/ //g'`
        check_item_in_set "$SANITIZED_RECORD" "${INVALID_FINGERPRINT_RECORDS[@]}"
        if [ $? -eq 0 ]; then
            debug_msg "Detected invalid machine fingerprint"\
                "record value ($record)."
            continue
        fi
        debug_msg "Adding finger print record ($record) to valid record array."
        VALID_FINGERPRINT_RECORDS=( "${VALID_FINGERPRINT_RECORDS[@]}" "$SANITIZED_RECORD" )
    done
    if [ ${#VALID_FINGERPRINT_RECORDS[@]} -eq 0 ]; then
        debug_msg "No valid fingerprint records detected in set"\
            "(${FINGERPRINT_RECORDS[@]})."
        return 1
    fi
    debug_msg "Valid fingerprint records (${VALID_FINGERPRINT_RECORDS[@]})."
    echo ${VALID_FINGERPRINT_RECORDS[@]}
    return 0
}

function filter_fingerprint_part_number () {
    local DATA_BLOCK="$1"
    FINGERPRINT_RECORDS=(
        `echo "$DATA_BLOCK" | \
        grep 'Part Number:' | \
        cut -d ':' -f 2 | \
        sort -u | \
        sed -e 's/ //g'`
    )
    filter_fingerprint_records ${FINGERPRINT_RECORDS[@]}
    return $?
}

function filter_fingerprint_serial_number () {
    local DATA_BLOCK="$1"
    FINGERPRINT_RECORDS=(
        `echo "$DATA_BLOCK" | \
        grep 'Serial Number:' | \
        cut -d ':' -f 2 | \
        sort -u | \
        sed -e 's/ //g'`
    )
    filter_fingerprint_records ${FINGERPRINT_RECORDS[@]}
    return $?
}

function filter_fingerprint_manufacturer () {
    local DATA_BLOCK="$1"
    FINGERPRINT_RECORDS=(
        `echo "$DATA_BLOCK" | \
        grep 'Manufacturer:' | \
        cut -d ':' -f 2 | \
        sort -u | \
        sed -e 's/ //g'`
    )
    filter_fingerprint_records ${FINGERPRINT_RECORDS[@]}
    return $?
}

function filter_fingerprint_core_count () {
    local DATA_BLOCK="$1"
    FINGERPRINT_RECORDS=(
        `echo "$DATA_BLOCK" | \
        grep 'Core Count:' | \
        cut -d ':' -f 2 | \
        sort -u | \
        sed -e 's/ //g'`
    )
    filter_fingerprint_records ${FINGERPRINT_RECORDS[@]}
    return $?
}

function filter_fingerprint_type () {
    local DATA_BLOCK="$1"
    FINGERPRINT_RECORDS=(
        `echo "$DATA_BLOCK" | \
        grep 'Type:' | \
        cut -d ':' -f 2 | \
        sort -u | \
        sed -e 's/ //g'`
    )
    filter_fingerprint_records ${FINGERPRINT_RECORDS[@]}
    return $?
}

function filter_fingerprint_id () {
    local DATA_BLOCK="$1"
    FINGERPRINT_RECORDS=(
        `echo "$DATA_BLOCK" | \
        grep 'ID:' | \
        cut -d ':' -f 2 | \
        sort -u | \
        sed -e 's/ //g'`
    )
    filter_fingerprint_records ${FINGERPRINT_RECORDS[@]}
    return $?
}

function filter_fingerprint_size () {
    local DATA_BLOCK="$1"
    FINGERPRINT_RECORDS=(
        `echo "$DATA_BLOCK" | \
        grep 'Size:' | \
        cut -d ':' -f 2 | \
        sort -u | \
        sed -e 's/ //g'`
    )
    filter_fingerprint_records ${FINGERPRINT_RECORDS[@]}
    return $?
}

function filter_fingerprint_version () {
    local DATA_BLOCK="$1"
    FINGERPRINT_RECORDS=(
        `echo "$DATA_BLOCK" | \
        grep 'Version:' | \
        cut -d ':' -f 2 | \
        sort -u | \
        sed -e 's/ //g'`
    )
    filter_fingerprint_records ${FINGERPRINT_RECORDS[@]}
    return $?
}

function filter_fingerprint_vendor () {
    local DATA_BLOCK="$1"
    FINGERPRINT_RECORDS=(
        `echo "$DATA_BLOCK" | \
        grep 'Vendor:' | \
        cut -d ':' -f 2 | \
        sort -u | \
        sed -e 's/ //g'`
    )
    filter_fingerprint_records ${FINGERPRINT_RECORDS[@]}
    return $?
}

function filter_fingerprint_stock_keeping_unit () {
    local DATA_BLOCK="$1"
    FINGERPRINT_RECORDS=(
        `echo "$DATA_BLOCK" | \
        grep 'SKU Number:' | \
        cut -d ':' -f 2 | \
        sort -u | \
        sed -e 's/ //g'`
    )
    filter_fingerprint_records ${FINGERPRINT_RECORDS[@]}
    return $?
}

function filter_fingerprint_name () {
    local DATA_BLOCK="$1"
    FINGERPRINT_RECORDS=(
        `echo "$DATA_BLOCK" | \
        grep 'Name:' | \
        cut -d ':' -f 2 | \
        sort -u | \
        sed -e 's/ //g'`
    )
    filter_fingerprint_records ${FINGERPRINT_RECORDS[@]}
    return $?
}

function filter_fingerprint_universally_unique_identifier () {
    local DATA_BLOCK="$1"
    FINGERPRINT_RECORDS=(
        `echo "$DATA_BLOCK" | \
        grep 'UUID:' | \
        cut -d ':' -f 2 | \
        sort -u | \
        sed -e 's/ //g'`
    )
    filter_fingerprint_records ${FINGERPRINT_RECORDS[@]}
    return $?
}

function filter_fingerprint_product () {
    local DATA_BLOCK="$1"
    FINGERPRINT_RECORDS=(
        `echo "$DATA_BLOCK" | \
        grep 'Product' | \
        cut -d ':' -f 2 | \
        sort -u | \
        sed -e 's/ //g'`
    )
    filter_fingerprint_records ${FINGERPRINT_RECORDS[@]}
    return $?
}

# CONVERTORS

function convert_array_to_delimited_string () {
    local DELIMITER="$1"
    local ARRAY=( "${@:2}" )
    echo "${ARRAY[@]}" | sed "s/ /${DEFAULT['delimiter']}/g"
    return $?
}

# GENERAL

function create_data_checksum () {
    local DATA="$@"
    debug_msg "Computing checksum hash using"\
        "(${CHECKSUM_ALGORITHMS[$ISEEYOU_CHECKSUM]})."
    echo "$DATA" | ${CHECKSUM_ALGORITHMS[$ISEEYOU_CHECKSUM]} | \
        sed -e 's/-//g' -e 's/ //g'
    return $?
}

function generate_machine_fingerprint_from_pattern () {
    local CHECKSUM_ALGORITHM_LABEL="$1"
    local MACHINE_FINGERPRINT_PATTERN=( ${@:2} )
    debug_msg "$CHECKSUM_ALGORITHM_LABEL - (${MACHINE_FINGERPRINT_PATTERN[@]})"
    if [ ${#MACHINE_FINGERPRINT_PATTERN[@]} -eq 0 ]; then
        echo; error_msg "No machinge fingerprint pattern specified."
        return 1
    fi
    echo; FINGERPRINT_BUILDER=''
    for item in "${MACHINE_FINGERPRINT_PATTERN[@]}"; do
        FINGERPRINT_RESOURCE_VALUE=`fetch_machine_fingerprint_value "$item"`
        if [ -z "$FINGERPRINT_RESOURCE_VALUE" ]; then
            warning_msg "Could not fetch ${RED}$item${RESET} value."\
                "Ignoring resource."
            continue
        fi
        FINGERPRINT_BUILDER+=",$FINGERPRINT_RESOURCE_VALUE"
        if [ -z ${ISEEYOU_FINGERPRINT_CACHE[$item]} ]; then
            cache_machine_fingerprint_resource_value "$item" \
                "$FINGERPRINT_RESOURCE_VALUE"
        fi
        debug_msg "$FINGERPRINT_RESOURCE_VALUE - $FINGERPRINT_BUILDER"
        symbol_msg "${GREEN}$item${RESET}" \
            "${CYAN}$FINGERPRINT_RESOURCE_VALUE${RESET}"
    done
    SANITIZED_FINGERPRINT_BUILDER=`echo "$FINGERPRINT_BUILDER" | \
        sed -e 's/,,,/,/g' -e 's/,,/,/g' -e 's/^,//g' -e 's/,$//g'`
    echo; info_msg "Computing ${CYAN}$ISEEYOU_CHECKSUM${RESET} hash of"\
        "fingerprint pattern ${CYAN}$ISEEYOU_FINGERPRINT${RESET}..."
    CHECKSUM_VALUE=`create_data_checksum "$SANITIZED_FINGERPRINT_BUILDER"`
    EXIT_CODE=$?
    debug_msg "$SANITIZED_FINGERPRINT_BUILDER - $CHECKSUM_VALUE"
    write_to_file 'override' ${DEFAULT['tmp-file']} "$CHECKSUM_VALUE"
    debug_msg "$CHECKSUM_VALUE - $EXIT_CODE"
    symbol_msg "${BLUE}$ISEEYOU_CHECKSUM${RESET}" \
        "${CYAN}$CHECKSUM_VALUE${RESET}"
    return $EXIT_CODE
}

function cache_machine_fingerprint_resource_value () {
    local FINGERPRINT_RESOURCE="$1"
    local RESOURCE_VALUE="$2"
    ISEEYOU_FINGERPRINT_CACHE["$FINGERPRINT_RESOURCE"]="$RESOURCE_VALUE"
    debug_msg "Cached fingerprint ($FINGERPRINT_RESOURCE)"\
        "value ($RESOURCE_VALUE)."
    return 0
}

function process_machine_fingerprint_pattern () {
    local FINGERPRINT_PATTERN="$1"
    IFS=','
    PROCESSED_PATTERN=()
    for item in $FINGERPRINT_PATTERN; do
        PROCESSED_PATTERN=( ${PROCESSED_PATTERN[@]} "$item" )
    done
    IFS=' '
    if [ ${#PROCESSED_PATTERN[@]} -eq 0 ]; then
        error_msg "Something went wrong."\
            "Could not process machine fingerprint pattern"\
            "${RED}$FINGERPRINT_PATTERN${RESET}."
        return 1
    fi
    echo ${PROCESSED_PATTERN[@]}
    return 0
}

function three_second_delay () {
    for item in `seq 3`; do
        echo -n '.'; sleep 1
    done
    return 0
}

function create_file_checksum () {
    local FILE_PATH="$1"
    ${CHECKSUM_ALGORITHMS[$ISEEYOU_CHECKSUM]} "$FILE_PATH" | awk '{print $1}'
    return $?
}

function create_directory_checksum () {
    local DIR_PATH="$1"
    tar -cf - "$DIR_PATH" &> /dev/null | \
        ${CHECKSUM_ALGORITHMS[$ISEEYOU_CHECKSUM]} | \
        awk '{print $1}'
    return $?
}

function remove_directory () {
    local DIR_PATH="$1"
    check_directory_exists "$DIR_PATH"
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid directory path ${RED}$DIR_PATH${RESET}."
        return 1
    fi
    find "$DIR_PATH" -type f | xargs shred f -n 10 -z -u &> /dev/null
    rm -rf "$DIR_PATH" &> /dev/null
    return $?
}

function remove_file () {
    local FILE_PATH="$1"
    check_file_exists "$FILE_PATH"
    if [ $? -ne 0 ]; then
        echo; error_msg "Invalid file path ${RED}$FILE_PATH${RESET}."
        return 1
    fi
    shred -f -n 10 -z -u "$FILE_PATH" &> /dev/null
    rm -f "$FILE_PATH" &> /dev/null
    return $?
}

function write_to_file () {
    local WRITTER_MODE="$1"
    local TARGET_FILE_PATH="$2"
    local DATA="${@:3}"
    case "$WRITTER_MODE" in
        'append')
            echo "$DATA" >> "$TARGET_FILE_PATH"
            ;;
        'override')
            echo "$DATA" > "$TARGET_FILE_PATH"
            ;;
        *)
            echo; error_msg "Invalid file writter mode"\
                "${RED}$WRITTER_MODE${RESET}."
            ;;
    esac
    return $?
}

function log_message () {
    local LOG_LEVEL="$1"
    local OPTIONAL="$2"
    local MSG="${@:3}"
    check_logging_on
    if [ $? -ne 0 ]; then
        return 1
    fi
    check_loglevel_set "$LOG_LEVEL"
    if [ $? -ne 0 ]; then
        debug_msg "Log level ($LOG_LEVEL) is not set."
        return 2
    fi
    case "$LOG_LEVEL" in
        'SYMBOL')
            echo "${MAGENTA}`date`${RESET} - [ $OPTIONAL ]: $MSG" >> ${DEFAULT['log-file']}
            ;;
        *)
            echo "${MAGENTA}`date`${RESET} - [ $LOG_LEVEL ]: $MSG" >> ${DEFAULT['log-file']}
            ;;
    esac
    return $?
}

# ACTIONS

function action_set_log_lines () {
    echo; info_msg "Type log line number to display"\
        "or ${MAGENTA}.back${RESET}."
    while :
    do
        LINE_COUNT=`fetch_data_from_user "FileLines"`
        if [ $? -ne 0 ]; then
            echo; info_msg "Aborting action."
            return 1
        fi
        check_value_is_number "$LINE_COUNT"
        if [ $? -ne 0 ]; then
            echo; error_msg "Value ${RED}$LINE_COUNT${RESET}"\
                "is not a number."
            continue
        fi; break
    done
    echo; info_msg "About to set log viewer line count to"\
        "${WHITE}$LINE_COUNT${RESET}."
    fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        echo; info_msg "Aborting action."
        return 1
    fi
    set_log_line_count "$LINE_COUNT"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not set log viewer"\
            "line count to ${RED}$LINE_COUNT${RESET}."
    else
        echo; ok_msg "Successfully set log viewer"\
            "line count to ${GREEN}$LINE_COUNT${RESET}."
    fi
    return $EXIT_CODE
}

function action_set_log_file () {
    echo; info_msg "Type absolute log file path"\
        "or ${MAGENTA}.back${RESET}."
    while :
    do
        FILE_PATH=`fetch_data_from_user "FilePath"`
        if [ $? -ne 0 ]; then
            echo; info_msg "Aborting action."
            return 1
        fi
        check_file_exists "$FILE_PATH"
        if [ $? -ne 0 ]; then
            echo; error_msg "File ${RED}$FILE_PATH${RESET}"\
                "does not exist."
            continue
        fi; break
    done
    echo; info_msg "About to set ${YELLOW}$FILE_PATH${RESET} as log file."
    fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        echo; info_msg "Aborting action."
        return 1
    fi
    set_log_file "$FILE_PATH"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not set ${RED}$FILE_PATH${RESET}"\
            "as log file."
    else
        echo; ok_msg "Successfully set ${GREEN}$FILE_PATH${RESET}"\
            "as log file."
    fi
    return $EXIT_CODE
}

function action_set_temporary_file () {
    echo; info_msg "Type absolute temporary file path"\
        "or ${MAGENTA}.back${RESET}."
    while :
    do
        FILE_PATH=`fetch_data_from_user "FilePath"`
        if [ $? -ne 0 ]; then
            echo; info_msg "Aborting action."
            return 1
        fi
        check_file_exists "$FILE_PATH"
        if [ $? -ne 0 ]; then
            echo; error_msg "File ${RED}$FILE_PATH${RESET}"\
                "does not exist."
            continue
        fi; break
    done
    echo; info_msg "About to set ${YELLOW}$FILE_PATH${RESET} as temporary file."
    fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        echo; info_msg "Aborting action."
        return 1
    fi
    set_temporary_file "$FILE_PATH"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not set ${RED}$FILE_PATH${RESET}"\
            "as temporary file."
    else
        echo; ok_msg "Successfully set ${GREEN}$FILE_PATH${RESET}"\
            "as temporary file."
    fi
    return $EXIT_CODE
}

function action_set_hashing_algorithm () {
    VALID_CHECKSUM_LABELS=( `fetch_checksum_algorithm_labels` )
    while :
    do
        echo; info_msg "Select checksum hashing algorithm -"; echo
        HASHING_ALGORITHM=`fetch_selection_from_user 'Checksum' ${VALID_CHECKSUM_LABELS[@]}`
        if [ $? -ne 0 ]; then
            return 1
        fi; break
    done
    echo; info_msg "About to set hashing algorithm to ${CYAN}$HASHING_ALGORITHM${RESET}."
    fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        echo; info_msg "Aborting action."
        return 1
    fi
    set_checksum_algorithm "$HASHING_ALGORITHM"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not set ${BLUE}$SCRIPT_NAME${RESET} hashing algorithm to"\
            "${RED}$HASHING_ALGORITHM${RESET}."
    else
        echo; ok_msg "Successfully set hashing algorithm to"\
            "${GREEN}$HASHING_ALGORITHM${RESET}."
    fi
    return $EXIT_CODE
}

function action_set_logging_off () {
    check_logging_off
    if [ $? -eq 0 ]; then
        echo; warning_msg "Logging already is ${RED}OFF${RESET}."
        return 1
    fi
    echo; info_msg "About to set ${BLUE}$SCRIPT_NAME${RESET}"\
        "logging flag to ${RED}OFF${RESET}."
    fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        echo; info_msg "Aborting action."
        return 1
    fi
    set_iseeyou_logging "off"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not set ${BLUE}$SCRIPT_NAME${RESET}"\
            "logging flag to ${RED}OFF${RESET}."
    else
        echo; ok_msg "Successfully set logging flag to ${RED}OFF${RESET}."
    fi
    return $EXIT_CODE
}

function action_set_logging_on () {
    check_logging_on
    if [ $? -eq 0 ]; then
        echo; warning_msg "Logging already is ${GREEN}ON${RESET}."
        return 1
    fi
    echo; info_msg "About to set ${BLUE}$SCRIPT_NAME${RESET}"\
        "logging flag to ${GREEN}ON${RESET}."
    fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        echo; info_msg "Aborting action."
        return 1
    fi
    set_iseeyou_logging "on"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not set ${BLUE}$SCRIPT_NAME${RESET}"\
            "logging flag to ${RED}ON${RESET}."
    else
        echo; ok_msg "Successfully set logging flag to ${GREEN}ON${RESET}."
    fi
    return $EXIT_CODE
}

function action_set_fingerprint_pattern () {
    VALID_FINGERPRINT_PATTERNS=( `fetch_machine_fingerprint_pattern_labels` )
    while :
    do
        echo; info_msg "Select machine fingerprint pattern -"; echo
        FINGERPRINT_PATTERN_LABEL=`fetch_selection_from_user "Pattern" ${VALID_FINGERPRINT_PATTERNS[@]}`
        if [ $? -ne 0 ]; then
            echo; info_msg "Aborting action."
            return 1
        fi; break
    done
    debug_msg "Machine fingerprint pattern label fetched from user"\
        "($FINGERPRINT_PATTERN_LABEL)."
    FINGERPRINT_PATTERN=${MACHINE_FINGERPRINT_PATTERNS[$FINGERPRINT_PATTERN_LABEL]}
    debug_msg "Machine fingerprint pattern ($FINGERPRINT_PATTERN)."
    echo; display_formatted_fingerprint_pattern "$FINGERPRINT_PATTERN_LABEL" "$FINGERPRINT_PATTERN"
    fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        echo; info_msg "Aborting action."
        return 1
    fi
    set_iseeyou_fingerprint_pattern "$FINGERPRINT_PATTERN_LABEL"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not set machine fingerprint pattern"\
            "${RED}$FINGERPRINT_PATTERN_LABEL${RESET}."
    else
        echo; ok_msg "Successfully set machine fingerprint pattern"\
            "${GREEN}$FINGERPRINT_PATTERN_LABEL${RESET}."
    fi
    return $EXIT_CODE
}

function action_create_custom_fingerprint_pattern () {
    local PATTERN_LABEL="$1"
    local FINGERPRINT_PATTERN="$2"
    echo; fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        echo; info_msg "Aborting action."
        return 1
    fi
    set_fingerprint_pattern "$PATTERN_LABEL" "$FINGERPRINT_PATTERN"
    return $?
}

function action_clear_log_file () {
    check_file_exists "${DEFAULT['log-file']}"
    if [ $? -ne 0 ]; then
        echo; warning_msg "Log file ${RED}${DEFAULT['log-file']}${RESET}"\
            "not found."
        return 2
    fi
    echo; fetch_ultimatum_from_user "Are you sure about this? ${YELLOW}Y/N${RESET}"
    if [ $? -ne 0 ]; then
        echo; info_msg "Aborting action."
        return 1
    fi
    check_safety_on
    if [ $? -eq 0 ]; then
        echo; warning_msg "Safety is ${GREEN}ON${RESET}."\
            "Log file ${RED}${DEFAULT['log-file']}${RESET}"\
            "will not be cleared."
        return 3
    fi
    echo -n > "${DEFAULT['log-file']}"
    check_file_empty "${DEFAULT['log-file']}"
    if [ $? -ne 0 ]; then
        echo; error_msg "Something went wrong."\
            "Could not clear ${BLUE}$SCRIPT_NAME${RESET}"\
            "log file ${RED}${DEFAULT['log-file']}${RESET}."
        return 4
    fi
    echo; ok_msg "Successfully cleared ${BLUE}$SCRIPT_NAME${RESET}"\
        "log file ${GREEN}${DEFAULT['log-file']}${RESET}."
    return 0
}

function action_log_view_tail () {
    check_file_exists "${DEFAULT['log-file']}"
    if [ $? -ne 0 ]; then
        echo; warning_msg "Log file ${RED}${DEFAULT['log-file']}${RESET}"\
            "not found."
        return 1
    fi
    echo; tail -n ${DEFAULT['log-lines']} ${DEFAULT['log-file']}
    return $?
}

function action_log_view_head () {
    check_file_exists "${DEFAULT['log-file']}"
    if [ $? -ne 0 ]; then
        echo; warning_msg "Log file ${RED}${DEFAULT['log-file']}${RESET}"\
            "not found."
        return 1
    fi
    echo; head -n ${DEFAULT['log-lines']} ${DEFAULT['log-file']}
    return $?
}

function action_log_view_more () {
    check_file_exists "${DEFAULT['log-file']}"
    if [ $? -ne 0 ]; then
        echo; warning_msg "Log file ${RED}${DEFAULT['log-file']}${RESET}"\
            "not found."
        return 1
    fi
    echo; more ${DEFAULT['log-file']}
    return $?
}

function action_compare_machine_fingerprint () {
    local MACHINE_FINGERPRINT="$1"
    MACHINE_FINGERPRINT_PATTERN=`fetch_machine_fingerprint_pattern_by_label \
        "$ISEEYOU_FINGERPRINT"`
    if [ -z "$MACHINE_FINGERPRINT_PATTERN" ]; then
        echo; error_msg "Could not fetch machine fingerprint pattern"\
            "${RED}$MACHINE_FINGERPRINT_PATTERN${RESET}."
        return 1
    fi
    FINGERPRINT_PATTERN=( `echo "$MACHINE_FINGERPRINT_PATTERN" | sed 's/,/ /g'` )
    generate_machine_fingerprint_from_pattern "$ISEEYOU_CHECKSUM" ${FINGERPRINT_PATTERN[@]} &> /dev/null
    check_file_has_number_of_lines "${DEFAULT['tmp-file']}" 1
    if [ $? -ne 0 ]; then
        error_msg "Software failure! Could not generate machine fingerprint"\
            "from pattern "
        return 1
    fi
    echo; VALID_MACHINE_FINGERPRINT=`cat ${DEFAULT['tmp-file']}`
    check_identical_strings "$MACHINE_FINGERPRINT" "$VALID_MACHINE_FINGERPRINT"
    if [ $? -ne 0 ]; then
        nok_msg "Given machine fingerprint does not match generated."
        symbol_msg "${BLUE}$ISEEYOU_CHECKSUM${RESET}" \
            "${RED}$VALID_MACHINE_FINGERPRINT${RESET}."
    else
        ok_msg "It's a match! Given machine fingerprint matches generated."
        symbol_msg "${BLUE}$ISEEYOU_CHECKSUM${RESET}" \
            "${GREEN}$VALID_MACHINE_FINGERPRINT${RESET}."
    fi
    return 0

}

function action_generate_machine_fingerprint () {
    local CHECKSUM_ALGORITHM_LABEL="$1"
    local MACHINE_FINGERPRINT_PATTERN="$2"
    FINGERPRINT_PATTERN=( `echo "$MACHINE_FINGERPRINT_PATTERN" | sed 's/,/ /g'` )
    debug_msg "Loaded machine fingerprint pattern (${FINGERPRINT_PATTERN[@]})"
    echo; info_msg "Generating machine fingerprint..."
    generate_machine_fingerprint_from_pattern "$CHECKSUM_ALGORITHM_LABEL" ${FINGERPRINT_PATTERN[@]}
    return $?
}

# HANDLERS

function handle_action_create_custom_fingerprint_pattern () {
    while :
    do
        echo; info_msg "Type custom fingerprint pattern label"\
            "or ${MAGENTA}.back${RESET}."
        CUSTOM_PATTERN_LABEL=`fetch_data_from_user 'Pattern'`
        if [ $? -ne 0 ]; then
            return 1
        fi
        check_valid_machine_fingerprint_pattern_label "$CUSTOM_PATTERN_LABEL"
        if [ $? -eq 0 ]; then
            echo; warning_msg "Machine fingerprint pattern label"\
                "${RED}$CUSTOM_PATTERN_LABEL${RESET} already taken."
            continue
        fi; break
    done

    while :
    do
        echo; info_msg "Type custom fingerprint pattern resources"\
            "separated by commas or ${MAGENTA}.back${RESET}."
        CUSTOM_FINGERPRINT_PATTERN=`fetch_data_from_user 'Pattern'`
        if [ $? -ne 0 ]; then
            return 1
        fi
        check_valid_fingerprint_pattern "$CUSTOM_FINGERPRINT_PATTERN"
        if [ $? -ne 0 ]; then
            echo; warning_msg "Invalid machine fingerprint pattern."
            continue
        fi; break
    done

    action_create_custom_fingerprint_pattern "$CUSTOM_PATTERN_LABEL" \
        "$CUSTOM_FINGERPRINT_PATTERN"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo; warning_msg "Something went wrong."\
            "Could not crete custom machine fingerprint pattern"\
            "${RED}$CUSTOM_PATTERN_LABEL${RESET}."
    else
        echo; ok_msg "Successfully created custom fingerprint pattern"\
            "${GREEN}$CUSTOM_PATTERN_LABEL${RESET}."
        display_formatted_fingerprint_pattern "$CUSTOM_PATTERN_LABEL" \
            "$CUSTOM_FINGERPRINT_PATTERN"
    fi
    return $EXIT_CODE
}

function handle_action_compare_machine_fingerprint () {
    while :
    do
        echo; info_msg "Type machine fingerprint or ${MAGENTA}.back${RESET}."
        MACHINE_FINGERPRINT=`fetch_data_from_user 'Fingerprint'`
        if [ $? -ne 0 ]; then
            return 1
        fi
        break
    done
    action_compare_machine_fingerprint "$MACHINE_FINGERPRINT"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not compare machine fingerprint using"\
            "${CYAN}$ISEEYOU_CHECKSUM${RESET} hashed pattern"\
            "${RED}$ISEEYOU_FINGERPRINT${RESET}."
    else
        ok_msg "Successfully generated machine fingerprint using"\
            "${CYAN}$ISEEYOU_CHECKSUM${RESET} hashed pattern"\
            "${GREEN}$ISEEYOU_FINGERPRINT${RESET}."
    fi
    return $EXIT_CODE
}

function handle_action_generate_machine_fingerprint () {
    MACHINE_FINGERPRINT_PATTERN=`fetch_machine_fingerprint_pattern_by_label \
        "$ISEEYOU_FINGERPRINT"`
    if [ -z "$MACHINE_FINGERPRINT_PATTERN" ]; then
        echo; error_msg "Could not fetch machine fingerprint pattern"\
            "${RED}$MACHINE_FINGERPRINT_PATTERN${RESET}."
        return 1
    fi
    action_generate_machine_fingerprint "$ISEEYOU_CHECKSUM" \
        "$MACHINE_FINGERPRINT_PATTERN"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        warning_msg "Something went wrong."\
            "Could not generate machine fingerprint using pattern"\
            "${RED}$ISEEYOU_FINGERPRINT${RESET}."
    else
        ok_msg "Successfully generated machine fingerprint using pattern"\
            "${GREEN}$ISEEYOU_FINGERPRINT${RESET}."
    fi
    return $EXIT_CODE
}

# CONTROLLERS

function iseeyou_log_viewer_controller () {
    OPTIONS=(
        'Display Log Tail'
        'Display Log Head'
        'Display More'
        'Clear Log File'
        'Back'
    )
    echo; symbol_msg "${BLUE}$SCRIPT_NAME${RESET}" \
        "${CYAN}Log Viewer${RESET}"; echo
    select opt in "${OPTIONS[@]}"; do
        case "$opt" in
            'Display Log Tail')
                action_log_view_tail; break
                ;;
            'Display Log Head')
                action_log_view_head; break
                ;;
            'Display More')
                action_log_view_more; break
                ;;
            'Clear Log File')
                action_clear_log_file; break
                ;;
            'Back')
                return 1
                ;;
            *)
                echo; warning_msg "Invalid option."; continue
                ;;
        esac
    done
    return 0
}

function iseeyou_control_panel () {
    OPTIONS=(
        'Custom Fingerprint Pattern'
        'Set Fingerprint Pattern'
        'Set Logging ON'
        'Set Logging OFF'
        'Set Hashing Algorithm'
        'Set Temporary File'
        'Set Log File'
        'Set Log Lines'
        'Install Dependencies'
        'Back'
    )
    display_settings; symbol_msg "${BLUE}$SCRIPT_NAME${RESET}" \
        "${CYAN}Control Panel${RESET}"; echo
    select opt in "${OPTIONS[@]}"; do
        case "$opt" in
            'Custom Fingerprint Pattern')
                handle_action_create_custom_fingerprint_pattern; break
                ;;
            'Set Fingerprint Pattern')
                action_set_fingerprint_pattern; break
                ;;
            'Set Logging ON')
                action_set_logging_on; break
                ;;
            'Set Logging OFF')
                action_set_logging_off; break
                ;;
            'Set Hashing Algorithm')
                action_set_hashing_algorithm; break
                ;;
            'Set Temporary File')
                action_set_temporary_file; break
                ;;
            'Set Log File')
                action_set_log_file; break
                ;;
            'Set Log Lines')
                action_set_log_lines; break
                ;;
            'Install Dependencies')
                apt_install_full_clip_logic_sniper_dependencies; break
                ;;
            'Back')
                return 1
                ;;
            *)
                echo; warning_msg "Invalid option."
                continue
                ;;
        esac
    done
    return 0
}

function iseeyou_main_controller () {
    OPTIONS=(
        'Inspect Machine'
        'Generate Fingerprint'
        'Compare Fingerprint'
        'Control Panel'
        "${BLUE}$SCRIPT_NAME${RESET} Log Viewer"
        'Back'
    )
    echo; symbol_msg "${BLUE}$SCRIPT_NAME${RESET}" \
        "${CYAN}Silent S.O.N.A.R.${RESET}"; echo
    select opt in "${OPTIONS[@]}"; do
        case "$opt" in
            'Inspect Machine')
                echo; symbol_msg "${BLUE}$SCRIPT_NAME${RESET}" \
                    "Scanning machine for fingerprint data preview..."
                echo; display_all_machine_data; break
                ;;
            'Generate Fingerprint')
                handle_action_generate_machine_fingerprint; break
                ;;
            'Compare Fingerprint')
                handle_action_compare_machine_fingerprint; break
                ;;
            'Control Panel')
                init_iseeyou_control_panel; break
                ;;
            "${BLUE}$SCRIPT_NAME${RESET} Log Viewer")
                init_iseeyou_log_viewer; break
                ;;
            'Back')
                clear; ok_msg "Terminating ${BLUE}$SCRIPT_NAME${RESET}.
                "; return 1
                ;;
            *)
                ;;
        esac
    done
    return $?
}

# INIT

function init_iseeyou_log_viewer () {
    while :
    do
        iseeyou_log_viewer_controller
        if [ $? -ne 0 ]; then
            break
        fi
    done
    return 0
}

function init_iseeyou_control_panel () {
    while :
    do
        iseeyou_control_panel
        if [ $? -ne 0 ]; then
            break
        fi
    done
    return 0
}

function init_iseeyou_main_controller () {
    display_banner
    check_preview_on
    if [ $? -eq 0 ]; then
        echo; symbol_msg "${BLUE}$SCRIPT_NAME${RESET}" \
            "Scanning machine for fingerprint data preview..."
        echo; display_all_machine_data
    fi
    while :
    do
        iseeyou_main_controller
        if [ $? -ne 0 ]; then
            break
        fi
    done
    return 0
}

# DISPLAY

function display_formatted_fingerprint_pattern () {
    local PATTERN_LABEL="$1"
    local FINGERPRINT_PATTERN="$2"
    symbol_msg "${CYAN}$PATTERN_LABEL${RESET}" \
        "${BLUE}$ISEEYOU_CHECKSUM${RESET}(${MAGENTA}$FINGERPRINT_PATTERN${RESET})"
    return $?
}

function display_formatted_flag () {
    local FLAG="$1"
    case "$FLAG" in
        'on'|'On'|'oN'|'ON')
            DISPLAY_FLAG="${GREEN}ON${RESET}"
            ;;
        'off'|'Off'|'OFf'|'OfF'|'ofF'|'OFF')
            DISPLAY_FLAG="${RED}OFF${RESET}"
            ;;
        *)
            DISPLAY_FLAG="$FLAG"
            ;;
    esac
    echo "$DISPLAY_FLAG"
    return $?
}

function display_settings () {
    DISPLAY_LOGGING=`display_formatted_flag "$ISEEYOU_LOGGING"`
    echo "
[ ${CYAN}Fingerprint Pattern${RESET}   ]: ${MAGENTA}$ISEEYOU_FINGERPRINT${RESET}
[ ${CYAN}Hashing Algorithm${RESET}     ]: ${MAGENTA}$ISEEYOU_CHECKSUM${RESET}
[ ${CYAN}Temporary File${RESET}        ]: ${YELLOW}${DEFAULT['tmp-file']}${RESET}
[ ${CYAN}Log File${RESET}              ]: ${YELLOW}${DEFAULT['log-file']}${RESET}
[ ${CYAN}Log Lines${RESET}             ]: ${WHITE}${DEFAULT['log-lines']}${RESET}
[ ${CYAN}Logging${RESET}               ]: $DISPLAY_LOGGING
    "
    return $?
}

function display_banner () {
    clear; echo; figlet -f lean "ISEEYOU" > ${DEFAULT['tmp-file']}
    echo "${BLUE}`cat ${DEFAULT['tmp-file']}`${RESET}"
    echo "            - ${RED}Regards, the Alveare Solutions society${RESET} -"
    return $?
}

function display_all_machine_data () {
    echo -n > ${DEFAULT['tmp-file']}
    for item in ${!ISEEYOU_FINGERPRINT_VALUES[@]}; do
        VALUE=`${ISEEYOU_FINGERPRINT_VALUES[$item]}`
        symbol_msg "${BLUE}$item${RESET}" "$VALUE" >> ${DEFAULT['tmp-file']}
    done
    cat ${DEFAULT['tmp-file']} | column
    echo -n > ${DEFAULT['tmp-file']}
    return 0
}

function debug_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    log_message 'SYMBOL' "${MAGENTA}DEBUG${RESET}" "$MSG"
    return 0
}

function done_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ ${BLUE}DONE${RESET} ]: $MSG"
    log_message 'SYMBOL' "${BLUE}DONE${RESET}" "$MSG"
    return 0
}

function ok_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ ${GREEN}OK${RESET} ]: $MSG"
    log_message 'SYMBOL' "${GREEN}OK${RESET}" "$MSG"
    return 0
}

function nok_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ ${RED}NOK${RESET} ]: $MSG"
    log_message 'SYMBOL' "${RED}NOK${RESET}" "$MSG"
    return 0
}

function qa_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ ${YELLOW}Q/A${RESET} ]: $MSG"
    log_message 'SYMBOL' "${YELLOW}Q/A${RESET}" "$MSG"
    return 0
}

function info_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ ${YELLOW}INFO${RESET} ]: $MSG"
    log_message 'SYMBOL' "${YELLOW}INFO${RESET}" "$MSG"
    return 0
}

function error_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ ${RED}ERROR${RESET} ]: $MSG"
    log_message 'SYMBOL' "${RED}ERROR${RESET}" "$MSG"
    return 0
}

function warning_msg () {
    local MSG="$@"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ ${RED}WARNING${RESET} ]: $MSG"
    log_message 'SYMBOL' "${RED}WARNING${RESET}" "$MSG"
    return 0
}

function symbol_msg () {
    local SYMBOL="$1"
    local MSG="${@:2}"
    if [ -z "$MSG" ]; then
        return 1
    fi
    echo "[ $SYMBOL ]: $MSG"
    log_message 'SYMBOL' "$SYMBOL" "$MSG"
    return 0
}

# MISCELLANEOUS

check_privileged_access
if [ $? -ne 0 ]; then
    echo; warning_msg "${BLUE}$SCRIPT_NAME${RESET} requires elevated"\
        "privileges. Are you root?
        "
    exit 1
fi

# TESTING AREA

init_iseeyou_main_controller
