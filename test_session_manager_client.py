import unittest
import logging
import base64
from db.interface import Database
from concurrent import futures
import grpc
from db import Credential, Device, Execution, Subprocess
import session_pb2_grpc as sm_pb2_grpc
import session_pb2 as sm_pb2

from session_manager_server import SessionManagerServicer, SessionManagerServer, Status, Tag

class TestSessionManagerServer(unittest.TestCase):
    port = 50000
    def setUp(self):
        self.img = ""
        self.access_token= "0A"
        self.timeout =20
        self.min_token = 23
        self.db = Database(db_file="test_sessions.db", db_create=True)       
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=20))
        sm_pb2_grpc.add_SessionManagerServicer_to_server(
            SessionManagerServicer(db_session=self.db,
                                   timeout=self.timeout), self.server )
        self.server.add_insecure_port("[::]:{}".format(self.port))
        logging.basicConfig(format="%(asctime)s - [%(levelname)8s] "
                           "- %(name)s - %(message)s", level=logging.INFO)
        log = logging.getLogger("session_manager")
        log.info("Starting SessionManagerServer at localhost:{}".format(
            self.port))
        self.server.start()

    
    def tearDown(self):
        self.server.stop(0)

    def signup(self, stub, username, password):
        response = stub.signup(sm_pb2.SignupInput(username=username,
                                                password=password
                                                ))
        return response
    def login(self, stub, username, password, device_name):
        response = stub.login(sm_pb2.LoginInput(username=username,
                                                password=password,
                                                device_name = device_name  ))
        return response

    def logout(self, stub, device_name, access_token):
        r,_ = stub.logout.with_call(sm_pb2.LogoutInput(device_name = 'samsung'   ) , 
                                        metadata=(("access_token", access_token),))
        return r

    def userInfo(self, stub, access_token):
        r,some= stub.userInfo.with_call(sm_pb2.UserInfoInput(some = "frame"   ) , 
                                        metadata=(("access_token", access_token),))
        return r

    def Execute(self, stub, device_name, access_token, img):
        with open(img, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())
            img_path = encoded_string

            features= stub.execute(sm_pb2.ExecutionInput(base64 = img_path   ) , 
                                        metadata=(("access_token", access_token),))
    
        for feature in features:
            if feature.tag != "yolo_output":
                print("tag: {tag} log {log} ".format(tag = feature.tag, log=feature.log_info))
            
        return features

    def previousTasks(self, stub, access_token , offset , index):
        r,some= stub.previousTasks.with_call(sm_pb2.PreviousTasksInput( offset = offset, index = index  ) , 
                                        metadata=(("access_token", access_token),))
        print(r)
        return print(type(r))
    # def subprocessInfo(self, stub, access_token):
    #         r,some = stub.subprocessInfo.with_call(sm_pb2.SubProcessInfoInput(metadata = (("access_token", access_token),)))
    #         print(r)
    #         return print(type(r))

    # Different test cases
    def test_cases(self):
        with grpc.insecure_channel("localhost:{}".format(50000)) as channel:
            stub = sm_pb2_grpc.SessionManagerStub(channel)

            # unittest for signup of the new user
            user_1 = self.signup(stub, "username_1", "password1")
            cred = self.db.query(Credential, username="username_1", password="password1")
            hash_password = cred.password
            self.assertIsNotNone(cred, "is not None")
            self.assertEqual(cred.username, "username_1")
            self.assertEqual(cred.password, hash_password)
            self.assertEqual(user_1.status, Status.OK)

            # unittest for First login (device_1) creates an entry with an access_token
            device_1 = self.login(stub, "username_1", "password1", "nokia")
            self.assertIsNotNone(device_1.access_token, "is not none")
            self.access_token = device_1.access_token

            device = self.db.query(Device, username="username_1", device_name="nokia")
            device_name = device.device_name

            self.assertEqual(self.access_token, device.access_token)            
            self.assertIsNotNone(device, "Device not found!")
            
            # let check for the userinfo

            userinfo = self.userInfo(stub, self.access_token)
            self.assertEqual(userinfo.username, cred.username)
            self.assertEqual(userinfo.balance, cred.token)

            # check for execution
            self.img = "dog.jpeg"
            execution = self.db.add(Execution, 
                                    input_image = self.img,
                                    username = "username_1")
            execution = self.db.query(Execution, username = "username_1")
            self.assertIsNotNone(execution, "execution is not None")

            features = self.Execute(stub, device_name, self.access_token, self.img)
            
            for feature in features:
                if feature.tag == Tag.YOLO_RESULT:
                    self.assertEqual(feature.tag, Tag.YOLO_RESULT)
                elif feature.tag == Tag.BAD_RESULT:
                    self.assertEqual(feature.tag, Tag.BAD_RESULT)
                elif feature.tag == Tag.CNTK_RESULT:
                    self.assertEqual(feature.tag, Tag.CNTK_RESULT)
                elif feature.tag == Tag.YOLO_OUTPUT:
                    self.assertEqual(feature.tag, Tag.YOLO_OUTPUT)
                elif feature.tag == Tag.YOLO_STAT:
                    self.assertEqual(feature.tag, Tag.YOLO_STAT)
                elif feature.tag == Tag.CNTK_STAT:
                    self.assertEqual(feature.tag, Tag.CNTK_STAT)

            # unittest for the previoustask
            previoustask = self.previousTasks(stub, self.access_token, 2, 0)
            self.assertIsNone(previoustask, "None")

            # unittest for subprocessinfo

            # logout signed user and erase access token
            out = self.logout(stub, device_name, self.access_token)

            self.assertEqual(out.status, Status.OK)

            device = self.db.query(Device,
                               username="username_1",
                               device_name="nokia")
            cred = self.db.query(Credential, 
                                username = "username_1", 
                                password = "password1")
            self.assertIsNotNone(cred, "is not none")
            self.assertEqual(device.access_token, "")
if __name__ == "__main__":
    unittest.main()
