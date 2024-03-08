#!/bin/bash

# Static script variables
script_name=$(basename "$0")
current_path=$(pwd)
cipher_software=(OpenSSL GPG)
crypto_directions=(encrypt decrypt)
crypto_types=(symmetric asymmetric)
cipher_algorithm_type=""
crypto_command=""
crypto_direction=""
crypto_type=""
gpg_extension=".gpg"
openssl_extension=".enc"
skipped_extensions=($gpg_extension $openssl_extension ".pem")
openssl_asymmetric_public="./certs/certificate.pem"
openssl_asymmetric_private="./certs/privatekey.pem"

# ANSI escape codes for text colors
RED='\033[0;31m'
GRAY='\033[0;90m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
RESET='\033[0m'
# Reset to default color

display_logo() {
    echo -e "${GREEN}"
    echo -e "   ____ __     __    _    ___                ___"
    echo -e "  / _(_) /__ _/_/__ | |  |_  |  ___  ___    <  /"
    echo -e " / _/ / / -_) /(_-< / / / __/  / _ \/ _ \   / / "
    echo -e "/_//_/_/\__/ //___//_/ /____/ /_//_/\___/  /_/  "
    echo -e "           |_|   /_/                            "
    echo -e "${RESET}"
}

is_gpg_installed() {
    if command -v gpg &> /dev/null; then
        return 0
    else
        return 1
    fi
}

is_openssl_installed() {
    if command -v openssl &> /dev/null; then
        return 0
    else
        return 1
    fi
}

get_openssl_symmetric_algos_array() {
    openssl_ciphers=($(openssl enc -list | grep -vE 'Supported|ciphers:'))
    counter=0
    for cipher in "${openssl_ciphers[@]}"; do
        echo -e "${CYAN}$cipher [$counter]${RESET}"
        counter=$((counter + 1))
    done
}

get_gpg_symmetric_algos_array() {

    # Run gpg --version and filter lines containing 'Cipher:'
    cipher_output_line_1=$(gpg --version | grep 'Cipher:')
    # Remove 'Cipher: ' from the variable
    ciphers_line1=${cipher_output_line_1#Cipher: }
    cipher_output_line_2=$(gpg --version | awk '/Cipher:/ { getline; print }')

    # Convert the comma-separated list to an array
    # IFS stands for "internal field separator". 
    # It is used by the shell to determine how to do word splitting, i. e. how to recognize word boundaries.
    IFS=', ' read -r -a cipher_array1 <<< "$ciphers_line1"
    IFS=', ' read -r -a cipher_array2 <<< "$cipher_output_line_2"

    # Merge arrays using concatenation
    cipher_array=("${cipher_array1[@]}" "${cipher_array2[@]}")    

    # Extract ciphers using awk
    # ciphers=$(echo "$cipher_output" | awk '/Cipher:/ { for(i=2; i<=NF; i++) print $i }')
    # Print each cipher in the array
    counter=0
    for cipher in "${cipher_array[@]}"; do
        echo -e "$cipher [$counter]"
        counter=$((counter + 1))
    done
}

overwrite_file_before_remove() {
    local file="$1"
    if [ -f $file ]; then
      read blocks blocksize < <(stat -c "%d %B" $file)
      echo "[${blocks} in ${blocksize}] - ${file}"
      dd if=/dev/urandom bs=${blocksize} count=${blocks} of=${file} conv=notrunc
    fi  
}

decrypted_file_handling() {
    local decrypted_out_file_name="$1"
    local is_overwrite="$2"

    if [ -f ${decrypted_out_file_name} ]; then
        echo -e "${GREEN}Decypted file '$decrypted_out_file_name' created.${RESET}"

        # if is derypted file is a tar archive ask for extract
        if [[ -f ${decrypted_out_file_name} &&  ${decrypted_out_file_name} == *.tar ]]; then
            extract_dir_folder="${decrypted_out_file_name%.tar}"

            read -p "Do you want to extract '$decrypted_out_file_name' to the folder '$extract_dir_folder'  file(s) [y/n]: " extract_decrypted_file
            if [[ ${extract_decrypted_file} == "y" ]]; then
                mkdir -p ${extract_dir_folder}
                if [[ -d  ${extract_dir_folder} ]]; then
                    tar -xvf ${decrypted_out_file_name} -C ${extract_dir_folder} 2>&1
                    cmd_output=$?
                    if [ $cmd_output -eq 0 ]; then
                        echo -e "${BLUE}The file '$decrypted_out_file_name' has been extracted successfully.${RESET}"
                        if [[ $is_overwrite == true ]]; then
                            echo -e "${YELLOW}Overwriting file: $decrypted_out_file_name${RESET}"
                            overwrite_file_before_remove "$decrypted_out_file_name"
                        fi
                        rm -r ${decrypted_out_file_name}
                        echo -e "${GREEN}Archive ${YELLOW}'$decrypted_out_file_name' is deleted.${RESET}"
                    else
                        echo -e "${YELLOW}Failed to extract '$decrypted_out_file_name' archive file to the folder '$extract_dir_folder'.${RESET}"
                    fi
                fi
            fi
        fi
    else
        echo -e "${RED}Decypted file with the name '$decrypted_out_file_name' is not found.${RESET}"
        exit 1
    fi
}

encrypted_file_handling() {
    local tar_name="$1"
    local encrypted_file_name="$2"
    local is_overwrite="$3"
    local archive_targets=("${@:4}")

    if [ -f ${tar_name} ]; then
        if [[ $is_overwrite == true ]]; then
            echo -e "${YELLOW}Overwriting file: $tar_name${RESET}"
            overwrite_file_before_remove "$tar_name"
        fi

        rm -r ${tar_name}
        echo -e "${GREEN}$tar_name removed.${RESET}"
        read -p "Will you choose to delete unencrypted file(s) and folder(s)? [y/n]: " is_unencrypted_remove
        if [[ ${is_unencrypted_remove} == "y" ]]; then
            for dir_object in "${archive_targets[@]}"; do
                # Expand the subfolder files display
                echo -e "${MAGENTA}Will be removed: $dir_object${RESET}"
            done

            read -p "Will you manually delete the unencrypted files? [y/n]: " is_unencrypted_remove_agree
            if [[ ${is_unencrypted_remove_agree} == "n" ]]; then
                for dir_object in "${archive_targets[@]}"; do
                    if [ -d $dir_object ]; then
                        for subfolder_file in $(find "./$dir_object" -type f); do
                            if [[ $is_overwrite == true ]]; then
                                echo -e "${YELLOW}Overwriting file: $subfolder_file${RESET}"
                                overwrite_file_before_remove "$subfolder_file"
                            fi
                            rm -r ${subfolder_file}
                        done
                        rmdir -p ${dir_object}
                    fi

                    if [ -f $dir_object ]; then
                        if [[ $is_overwrite == true ]]; then
                            echo -e "${YELLOW}Overwriting file: $dir_object${RESET}"
                            overwrite_file_before_remove "$dir_object"
                        fi
                        rm -r ${dir_object}
                    fi

                    echo -e "${GREEN}$dir_object successfully removed.${RESET}"
                done
            fi
        fi
        echo -e "${BLUE}Encrypted container '$encrypted_file_name' successfully created. Do not forget the cipher type and password.${RESET}"
    fi
}

execute_flush_action() {
    is_overwrite="$1"
    local skipped_extensions=("${@:2}")

    for file in $(find . -type  f); do
        file_base=$(basename "$file")

        skip_removal=false
        for ext in "${skipped_extensions[@]}"; do
            if [[ "$file_base" == *"$ext" ]]; then
                skip_removal=true
                break
            fi
        done

        if [ -f $file ]; then
            if [[ $skip_removal == false && "$script_name" != "$file_base" ]]; then
                if [[ $is_overwrite == true ]]; then
                    echo -e "${YELLOW}Overwriting file: $file${RESET}"
                    overwrite_file_before_remove "$file"
                fi

                echo -e "${RED}Deleting file: $file${RESET}"
                rm -r ${file}
            fi
        fi
    done

    # Remove empty directories
    for file in $(find . -type d); do
        rmdir -p -v $file
    done
}

execute_panic_action() {
    is_overwrite="$1"
    for file in $(find . -type  f); do
        if [ -f $file ]; then
            if [[ $is_overwrite == true ]]; then
                echo -e "${YELLOW}Overwriting file: $file${RESET}"
                overwrite_file_before_remove "$file"
            fi
            echo -e "${RED}Deleting file: $file${RESET}"
            rm -r ${file}
        fi
    done

    # Remove empty directories
    for file in $(find . -type d); do
        rmdir -p -v $file
    done
}

# [Options]:
# '-o' or '--overwrite'
OVERWRITE=false

# -f|--flush
FLUSHDATA=false

# -p|--panic
PANICATTACK=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
        echo "Usage: $0 [options]"
        echo "Options:"
        echo "  -h|--help           Display this help message."
        echo "  -o|--overwrite      Overwrite the file with random ASCII symbols before it is removed. This is done to prevent data recovery."
        echo "                      Notice: use this option only with linux filesystems."
        echo "  -f|--flush          Flush folder from the unencrypted data. It can work together with [-o|--overwrite] option."
        echo "  -p|--panic          Clean all files and folders at the script location, including the executable script. It can work together with [-o|--overwrite] option."
        echo "                      Notice: The current option does not require your agreement and will be executed immediately."
        echo "The OpenSSL symmetric ciphers list is extensive, but not every cipher is compatible with encrypting TAR files."
        echo "  Please choose ciphers with the postfix '-cbc'."
        echo ""
        echo "The OpenSSL command reminder for generating asymmetric key pairs:"
        echo "  openssl req -x509 -newkey rsa:4096 -keyout <privatekey.pem> -out <publickey.pem> -days <numeric>"
        echo ""
        echo "The GnuPG command reminder for generating asymmetric key pairs:"
        echo "  gpg --full-generate-key | gpg --gen-key"
        exit 0
        ;;
    -o|--overwrite)
      OVERWRITE=true
      ;;
    -f|--flush)
      FLUSHDATA=true
      ;;
    -p|--panic)
      PANICATTACK=true
      ;;
    *)
      echo "Error: Unknown option $1. Use -h or --help for usage."
      exit 1
      ;;
  esac
  shift
done

display_logo

if [[ $FLUSHDATA == true ]]; then
 execute_flush_action "$OVERWRITE" "${skipped_extensions[@]}"
 exit 1
fi

if [[ $PANICATTACK == true ]]; then
    execute_panic_action "$OVERWRITE"
    exit 1
fi

#   1. Checking what kind of cryptography software is installed.
cryptography_software=()

if is_openssl_installed; then
    echo -e "${GREEN}openssl is installed${RESET}"
    cryptography_software+=('openssl (OpenSSL)')
else 
    echo -e "${RED}openssl is not installed${RESET}"
fi


if is_gpg_installed; then
    echo -e "${GREEN}gpg (GnuPG) is installed${RESET}"
    cryptography_software+=('gpg (GnuPG)')
else
    echo -e "${RED}gpg (GnuPG) is not installed${RESET}"
fi

if [[ "${#cryptography_software[@]}" > 0 ]]; then
    counter=0
    for crypto_soft_name in "${cryptography_software[@]}"; do
        echo -e "${BLUE}$crypto_soft_name [$counter]${RESET}"
        counter=$((counter + 1))
    done
    read -p "Please select the software number that is preferred [0-$(( ${#cryptography_software[@]} - 1 ))]: " crypto_soft_index
    
    if ((crypto_soft_index >= 0 && crypto_soft_index < ${#cryptography_software[@]})); then
        crypto_command_string=${cryptography_software[$crypto_soft_index]}
        # Extract 'gpg' using awk
        # result=$(echo "$original_string" | awk '{print $1}')
        #crypto_command=${crypto_command_string%% *}
        crypto_command=$(echo "$crypto_command_string" | awk '{print $1}')
        echo -e "Selected software: ${CYAN}$crypto_command${RESET}"
        
        counter=0
        for crypto_destination in "${crypto_directions[@]}"; do
            echo -e "${BLUE}$crypto_destination [$counter]${RESET}"
            counter=$((counter + 1))
        done
        read -p "Please select what you do [0-$(( ${#crypto_directions[@]} - 1 ))]: " crypto_direction_index
        if ((crypto_direction_index >= 0 && crypto_direction_index <  ${#crypto_directions[@]})); then
            crypto_direction=${crypto_directions[$crypto_direction_index]}
            echo -e "Selected direction: ${CYAN}$crypto_direction${RESET}"
        else
            echo -e "${RED}Selected number is not in a range${RESET}"
        fi

        # Symmetric/Asymmetric cipher types
        counter=0
        for crypto_type_value in "${crypto_types[@]}"; do
            echo -e "${BLUE}$crypto_type_value [$counter]${RESET}"
            counter=$((counter + 1))
        done

        read -p "Select number of the encryption type [0-$(( ${#crypto_types[@]} - 1 ))]: " crypto_type_index
        if((crypto_type_index >= 0 && crypto_type_index < ${#crypto_types[@]})); then
            crypto_type=${crypto_types[$crypto_type_index]}
            echo -e "Selected encryption type: ${CYAN}$crypto_type${RESET}"
        else
            echo -e "${RED}Selected number is not in a range${RESET}"
        fi

        # Get Symmetric algos list to select one from them - begin
        if [[ "$crypto_type" == "symmetric" ]]; then
            if [[ "$crypto_command" == "openssl" ]]; then
                openssl_ciphers=($(openssl enc -list | grep -vE 'Supported|ciphers:'))
                counter=0
                for cipher in "${openssl_ciphers[@]}"; do
                    echo -e "${CYAN}$cipher [$counter]${RESET}"
                    counter=$((counter + 1))
                done

                read -p "Select number of the cipher algorithm [0-$(( ${#openssl_ciphers[@]} - 1 ))]: " cipher_algo_index
                if((cipher_algo_index >= 0 && cipher_algo_index < ${#openssl_ciphers[@]})); then
                    cipher_algorithm_type=${openssl_ciphers[$cipher_algo_index]}
                    echo -e "Selected cipher algorithm: ${CYAN}$cipher_algorithm_type${RESET}"
                else
                    echo -e "${RED}Selected number is not in a range${RESET}"
                fi
            fi

            if [[ "$crypto_command" == "gpg" ]]; then
                # Run gpg --version and filter lines containing 'Cipher:'
                cipher_output_line_1=$(gpg --version | grep 'Cipher:')
                # Remove 'Cipher: ' from the variable
                ciphers_line1=${cipher_output_line_1#Cipher: }
                cipher_output_line_2=$(gpg --version | awk '/Cipher:/ { getline; print }')

                # Convert the comma-separated list to an array
                # IFS stands for "internal field separator". 
                # It is used by the shell to determine how to do word splitting, i. e. how to recognize word boundaries.
                IFS=', ' read -r -a cipher_array1 <<< "$ciphers_line1"
                IFS=', ' read -r -a cipher_array2 <<< "$cipher_output_line_2"

                # Merge arrays using concatenation
                cipher_array=("${cipher_array1[@]}" "${cipher_array2[@]}")    

                # Extract ciphers using awk
                # ciphers=$(echo "$cipher_output" | awk '/Cipher:/ { for(i=2; i<=NF; i++) print $i }')
                # Print each cipher in the array
                counter=0
                for cipher in "${cipher_array[@]}"; do
                    echo -e "${CYAN}$cipher [$counter]${RESET}"
                    counter=$((counter + 1))
                done

                read -p "Select number of the cipher algorithm [0-$(( ${#cipher_array[@]} - 1 ))]: " cipher_algo_index
                if((cipher_algo_index >= 0 && cipher_algo_index < ${#cipher_array[@]})); then
                    cipher_algorithm_type=${cipher_array[$cipher_algo_index]}
                    echo -e "Selected cipher algorythm: ${CYAN}$cipher_algorithm_type${RESET}"
                else
                    echo -e "${RED}Selected number is not in a range${RESET}"
                    exit 1
                fi
            fi
        fi # Get Symmetric algos list to select one from them - end

        # Encryption Logic - Begin
        if [[ "$crypto_direction" == "encrypt" ]]; then
            echo "The current path is '$current_path' and file(s) and directory(s) inside:"
            dirs_list=$(ls -lah "$current_path")
            counter=0
            while IFS= read -r dir_value; do
                dir_object=$(echo "$dir_value" | awk '{print $9}')
                if [[ -n "$dir_object" && "$dir_object" != "." && "$dir_object" != ".." ]]; then
                    echo -e "${MAGENTA}$dir_value [$counter]${RESET}"
                fi
                counter=$((counter + 1))
            done <<< "$dirs_list"

            read -p "Enter comma-separated numbers of file(s) or directory to create TAR archive: " selected_archive_objects
            # echo "Debug archive_objects: $selected_archive_objects"
            if [[ -n "$selected_archive_objects" ]]; then
                # Remove spaces after commas
                normalized_string=$(echo "$selected_archive_objects" | sed 's/, */,/g')
                # echo "Debug normalized selected_archive_objects: $normalized_string"

                archive_targets=()
                # Convert the comma-separated numbers into an array
                IFS=',' read -ra selected_objects_array <<< "$normalized_string"

                # Specify the files and subfolders to include in the tar archive
                for selected_dir_object in "${selected_objects_array[@]}"; do
                    # Ensure the selected number is within the valid range
                    if ((selected_dir_object >= 0 && selected_dir_object < counter)); then
                        selected_object=$(awk -v num="$selected_dir_object" 'NR == num+1 {print $9}' <<< "$dirs_list")
                        archive_targets+=("$selected_object")
                        echo -e "Selected object(s): ${CYAN}$selected_object${RESET}"
                    fi
                done
                # Remove the trailing space at the end of archive_targets
                archive_targets="${archive_targets% }"
                # echo -e "Archive object(s): ${CYAN}$archive_targets${RESET}"
            else
                echo -e "${RED}Selected number(s) is not in a range${RESET}"
                exit 1
            fi

            tar_name=""
            tar_extension=".tar"
            read -p "Specify TAR archive name. Generate random name [y/n]: " tar_is_rand

            if [[ "$tar_is_rand" == "y" ]]; then
                tar_random_name=$(head /dev/urandom | tr -dc a-z0-9 | head -c 8 ; echo '')
                tar_name="$tar_random_name$tar_extension"
                echo -e "The name of the intermediate archive file: ${CYAN}$tar_name${RESET}"
            else
                read -p "Enter TAR file name manually: " tar_custom_name
                if [[ "$tar_custom_name" != *"$tar_extension" ]]; then
                    tar_name="$tar_custom_name$tar_extension"
                else
                    tar_name="$tar_custom_name"
                fi
                echo -e "The name of the intermediate archive file: ${CYAN}$tar_name${RESET}"
            fi

            if [[ -n "$tar_name" ]]; then
                # Create tar file
                echo "tar -cvf $tar_name  ${archive_targets[@]}"
                tar -cvf "$tar_name" "${archive_targets[@]}"
                echo -e "${GREEN}Tar archive '$tar_name' created successfully.${RESET}"
                if [[ "$crypto_type" == "symmetric" ]]; then
                    echo -e "${YELLOW}The next dialog will ask you to input a secret phrase. This phrase should be memorable for you but not easily guessable by others.${RESET}"
                fi
            else
                echo -e "${RED}The TAR name is not specified.${RESET}"
                exit 1
            fi

            # Symmetric GPG encryption - begin
            if [[ "$crypto_command" == "gpg" && "$crypto_type" == "symmetric" ]]; then
                encrypted_tar_name="$tar_name$gpg_extension"
                gpg --out "$encrypted_tar_name" --symmetric --cipher-algo "$cipher_algorithm_type" "$tar_name" 2>&1
                cmd_output=$?

                # Check if the gpg command was successfull
                if [ $cmd_output -eq 0 ]; then
                    encrypted_file_handling ${tar_name} ${encrypted_tar_name} "$OVERWRITE" "${archive_targets[@]}"
                else
                     echo -e "${RED}Encryption failed. Error output: $cmd_output${RESET}"
                fi
            fi # Symmetric GPG encryption - end

            # Symmetric OpenSSl encryption - begin
            if [[ "$crypto_command" == "openssl" && "$crypto_type" == "symmetric" ]]; then
                encrypted_tar_name="$tar_name$openssl_extension"
                openssl enc ${cipher_algorithm_type} -salt -in ${tar_name} -out ${encrypted_tar_name} -pbkdf2 2>&1
                cmd_output=$?

                if [ $cmd_output -eq 0 ]; then
                    encrypted_file_handling ${tar_name} ${encrypted_tar_name} "$OVERWRITE" "${archive_targets[@]}"
                else
                    echo -e "${RED}Encryption failed. Error output: ${cmd_output}${RESET}"
                    exit 1
                fi
            fi # Symmetric OpenSSl encryption - end

            # Asymmetric GPG encryption - begin
            if [[ "$crypto_command" == "gpg" && "$crypto_type" == "asymmetric" ]]; then
                #   gpg --gen-key
                # --recipient cygwin@maila.net
                # --recipient cayen@avel.net
                encrypted_tar_name="$tar_name$gpg_extension"
                read -p "Provide recipient value of keys pair: " keys_pair_recipient

                # Remove the trailing space at the end of archive_targets
                if [[ -n $keys_pair_recipient ]]; then
                    pair_recipient="${keys_pair_recipient% }"
                    echo "Debug pair_recipient: $pair_recipient"
                    # gpg --encrypt --recipient ${pair_recipient} ${tar_name}
                    # gpg --decrypt --output 4mahv4ct.tar 4mahv4ct.tar.ex.gpg
                    gpg --encrypt --output ${encrypted_tar_name} --recipient ${pair_recipient} ${tar_name} 2>&1
                    cmd_output=$?

                    if [ $cmd_output -eq 0 ]; then
                        encrypted_file_handling ${tar_name} ${encrypted_tar_name} "$OVERWRITE" "${archive_targets[@]}"
                    else
                        echo -e "${RED}Encryption failed. Error output: ${cmd_output}${RESET}"
                        exit 1
                    fi
                else
                    echo -e "${RED}Recipient value can not be empty!${RESET}"
                    exit 1
                fi
            fi
            # Asymmetric GPG encryption - end

            # Asymmetric OpenSSL encryption - begin
            if [[ "$crypto_command" == "openssl" && "$crypto_type" == "asymmetric" ]]; then
                encrypted_tar_name="$tar_name$openssl_extension"
                # openssl rsautl -encrypt -pubin -inkey ${openssl_asymmetric_public} -in ${tar_name} -out ${encrypted_tar_name} 2>&1
                openssl smime -encrypt -binary -aes-256-cbc -in ${tar_name} -out ${encrypted_tar_name} -outform DER ${openssl_asymmetric_public}
                cmd_output=$?
                
                if [ $cmd_output -eq 0 ]; then
                    encrypted_file_handling ${tar_name} ${encrypted_tar_name} "$OVERWRITE" "${archive_targets[@]}"
                else
                    echo -e "${RED}Encryption failed. Error output: ${cmd_output}${RESET}"
                    exit 1
                fi
            fi
            # Asymmetric OpenSSL encryption - end
        fi # Encryption Logic - end

        # Decryption Logic - begin
        if [[ "$crypto_direction" == "decrypt" ]]; then

            dirs_list=$(ls -lah "$current_path")
            counter=0
            while IFS= read -r dir_value; do
                dir_object=$(echo "$dir_value" | awk '{print $9}')
                if [[ -n "$dir_object" && "$dir_object" != "." && "$dir_object" != ".." ]]; then
                    if [[ "$crypto_command" == "openssl" ]]; then
                        if [[ "$dir_object" == *"$openssl_extension" ]]; then
                            echo -e "${CYAN}$dir_value [$counter]${RESET}"
                        else
                            echo -e "${GRAY}$dir_value [$counter]${RESET}"
                        fi
                    fi

                    if [[ "$crypto_command" == "gpg" ]]; then
                        if [[ "$dir_object" == *"$gpg_extension" ]]; then
                            echo -e "${CYAN}$dir_value [$counter]${RESET}"

                        else
                            echo -e "${GRAY}$dir_value [$counter]${RESET}"
                        fi
                    fi
                fi
                counter=$((counter + 1))
            done <<< "$dirs_list"

            read -p "Select encrypted file number to decrypt [0-$((counter - 1))]: " selected_file_index
            # echo "Debug selected_file_index - basic: $selected_file_index"
            if ((selected_file_index >= 0 && selected_file_index < counter)); then
                selected_file_name=$(awk -v num="$selected_file_index" 'NR == num+1 {print $9}' <<< "$dirs_list")
                echo -e "Selected file: ${CYAN}$selected_file_name${RESET}"

                # If selected file is exists do decrypt
                if [ -f ${selected_file_name} ]; then

                    # Symmetric OpenSSl decryption - begin
                    if [[ "$crypto_command" == "openssl" && "$crypto_type" == "symmetric" ]]; then
                        decrypted_out_file_name="${selected_file_name%"$openssl_extension"}"
                        openssl enc -d ${cipher_algorithm_type} -in ${selected_file_name} -out ${decrypted_out_file_name} -pbkdf2 2>&1
                        cmd_output=$?
                        
                        if [ $cmd_output -eq 0 ]; then
                            decrypted_file_handling ${decrypted_out_file_name} "$OVERWRITE"
                            exit 1
                        else
                              echo -e "${RED}Decryption failed. Error output: ${cmd_output}${RESET}"
                              exit 1
                        fi
                    fi
                    # Symmetric OpenSSl decryption - end

                    # Symmetric GNUPG decryption - begin
                    if [[ "$crypto_command" == "gpg" && "$crypto_type" == "symmetric" ]]; then
                        decrypted_out_file_name="${selected_file_name%"$gpg_extension"}"
                        gpg --decrypt --output ${decrypted_out_file_name} ${selected_file_name} 2>&1
                        cmd_output=$?

                        if [ $cmd_output -eq 0 ]; then
                            decrypted_file_handling ${decrypted_out_file_name} "$OVERWRITE"
                            exit 1
                        else
                            echo -e "${RED}Decryption failed. Error output: ${cmd_output}${RESET}"
                            exit 1
                        fi
                    fi
                    # Symmetric GNUPG decryption - end

                    # Asymmetric GNUPG decryption - begin
                    if [[ "$crypto_command" == "gpg" && "$crypto_type" == "asymmetric" ]]; then
                        decrypted_out_file_name="${selected_file_name%"$gpg_extension"}"
                        gpg --decrypt --output ${decrypted_out_file_name} ${selected_file_name} 2>&1
                        cmd_output=$?

                        if [ $cmd_output -eq 0 ]; then
                            decrypted_file_handling ${decrypted_out_file_name} "$OVERWRITE"
                            exit 1
                        else
                            echo -e "${RED}Decryption failed. Error output: ${cmd_output}${RESET}"
                            exit 1
                        fi
                    fi
                    # Asymmetric GNUPG decryption - end
                    
                    # Asymmetric OpenSSL decryption - Begin
                    if [[ "$crypto_command" == "openssl" && "$crypto_type" == "asymmetric" ]]; then
                        decrypted_out_file_name="${selected_file_name%"$openssl_extension"}"
                        openssl smime -decrypt -binary -in ${selected_file_name} -inform DER -out ${decrypted_out_file_name} -inkey "$openssl_asymmetric_private" 2>&1
                        cmd_output=$?

                        if [ $cmd_output -eq 0 ]; then
                            decrypted_file_handling ${decrypted_out_file_name} "$OVERWRITE"
                            exit 1
                        else
                            echo -e "${RED}Decryption failed. Error output: ${cmd_output}${RESET}"
                            exit 1
                        fi
                    fi
                    # Asymmetric OpenSSL decryption - End
                else
                    echo -e "${RED}Failed file '$selected_file_name'. No such file."
                    exit 1
                fi

            else
                echo -e "${RED}Selected number is not in a range.${RESET}"
                exit 1
            fi
            
        fi
        # Decryption Logic - end

    else
        echo -e "${RED}Selected number is not in a range${RESET}"
        exit 1
    fi
else
    echo -e "${RED}The current shell uses one of the several software options, either OpenSSL or GnuPG. To install it on your system, you need to know how.${RESET}"
    exit 1
fi

# keyspair generator
# openssl req -x509 -newkey rsa:4096 -keyout privatekey.pem -out certificate.pem -days N-num

# encrypt large files openssl method
# openssl smime -encrypt -binary -aes-256-cbc -in 3dakax7o.tar -out 3dakax7o.tar.enc -outform DER ./keyspair/certificate.pem
# decrypt large openssl files
# openssl smime -decrypt -binary -in 3dakax7o.tar.enc -inform DER -out 3dakax7o-dec.tar -inkey ./keyspair/privatekey.pem -passin pass:my_secret

