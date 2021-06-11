from .helper import DownloadDataHelper, ProgressHelper, ProcessDataHelper, TrainMLHelper, EvaluationHelper, OtherHelper
import os


class Creme:
    mirai = True
    ransomware = True
    resource_hijacking = True
    disk_wipe = True
    end_point_dos = True

    data_theft = True
    rootkit_ransomware = True

    models_name = ["decision_tree", "naive_bayes", "extra_tree", "knn", "random_forest", "XGBoost"]

    # should update to allow users define weights on the website
    weights = {"attack_types": 4 / 10 / 20, "attack_scenarios": 2 / 10 / 20, "data_sources": 1 / 10 / 6,
               "labeled_data": 1 / 10 / 6, "feature_set": 1 / 10 / 6, "metadata": 1 / 10}

    def __init__(self, dls, target_server, benign_server, vulnerable_clients, non_vulnerable_clients,
                 attacker_server, malicious_client, mirai, ransomware, resource_hijacking, disk_wipe, end_point_dos,
                 data_theft, rootkit_ransomware):
        # self.stage = 0
        # self.status = 1
        # self.finishedTasks = []
        # self.messages = []
        # self.sizes = []
        # self.finishedStageList = []
        # Helper.clearProgressData()

        # Machines
        self.dls = dls
        self.target_server = target_server
        self.benign_server = benign_server
        self.vulnerable_clients = vulnerable_clients
        self.non_vulnerable_clients = non_vulnerable_clients
        self.attacker_server = attacker_server
        self.malicious_client = malicious_client

        # Attack scenarios. True/False
        Creme.mirai = mirai
        Creme.ransomware = ransomware
        Creme.resource_hijacking = resource_hijacking
        Creme.disk_wipe = disk_wipe
        Creme.end_point_dos = end_point_dos
        Creme.data_theft = data_theft
        Creme.rootkit_ransomware = rootkit_ransomware

        # prepare to build mirai source code
        if mirai:
            mirai_o4_xxx = "(o4 == 1 || o4 == 2 || o4 == 3"  # default gateway
            mirai_o4_xxx += " || o4 == " + attacker_server.ip.split(".")[-1]
            mirai_o4_xxx += " || o4 == " + malicious_client.ip.split(".")[-1]
            mirai_o4_xxx += " || o4 == " + target_server.ip.split(".")[-1]
            mirai_o4_xxx += " || o4 == " + benign_server.ip.split(".")[-1]
            mirai_o4_xxx += " || o4 == " + dls.ip.split(".")[-1]
            mirai_o4_xxx += " || o4 == " + self.dls.controller_ip.split(".")[-1]
            mirai_o4_xxx_1 = mirai_o4_xxx
            mirai_o4_xxx_2 = mirai_o4_xxx
            for vulnerable_client in vulnerable_clients:
                mirai_o4_xxx_2 += " || o4 == " + vulnerable_client.ip.split(".")[-1]
            mirai_o4_xxx_1 += ") ||"
            mirai_o4_xxx_2 += ") ||"
            self.attacker_server.mirai_o4_xxx_1 = mirai_o4_xxx_1
            self.attacker_server.mirai_o4_xxx_2 = mirai_o4_xxx_2

    def configure(self):
        stage = 1
        ProgressHelper.update_stage(stage, f"Controller is configuring {self.dls.hostname}", 5, new_stage=True)
        self.dls.configure()
        ProgressHelper.update_stage(stage, f"Controller FINISHED configuring {self.dls.hostname}", 5,
                                    finished_task=True, override_pre_message=True)

        ProgressHelper.update_stage(stage, f"Controller is configuring {self.target_server.hostname}", 5)
        self.target_server.configure()
        ProgressHelper.update_stage(stage, f"Controller FINISHED configuring {self.target_server.hostname}", 5,
                                    finished_task=True, override_pre_message=True)

        ProgressHelper.update_stage(stage, f"Controller is configuring {self.benign_server.hostname}", 5)
        self.benign_server.configure()
        ProgressHelper.update_stage(stage, f"Controller FINISHED configuring {self.benign_server.hostname}", 5,
                                    finished_task=True, override_pre_message=True)

        for vulnerable_client in self.vulnerable_clients:
            ProgressHelper.update_stage(stage, f"Controller is configuring {vulnerable_client.hostname}", 5)
            vulnerable_client.configure()
            ProgressHelper.update_stage(stage, f"Controller FINISHED configuring {vulnerable_client.hostname}", 5,
                                        finished_task=True, override_pre_message=True)

        for non_vulnerable_client in self.non_vulnerable_clients:
            ProgressHelper.update_stage(stage, f"Controller is configuring {non_vulnerable_client.hostname}", 5)
            non_vulnerable_client.configure()
            ProgressHelper.update_stage(stage, f"Controller FINISHED configuring {non_vulnerable_client.hostname}", 5,
                                        finished_task=True, override_pre_message=True)

        ProgressHelper.update_stage(stage, f"Controller is configuring {self.attacker_server.hostname}", 5)
        self.attacker_server.configure()
        ProgressHelper.update_stage(stage, f"Controller FINISHED configuring {self.attacker_server.hostname}", 5,
                                    finished_task=True, override_pre_message=True)

        ProgressHelper.update_stage(stage, f"Controller is configuring {self.malicious_client.hostname}", 5)
        self.malicious_client.configure()
        ProgressHelper.update_stage(stage, f"Controller FINISHED configuring {self.malicious_client.hostname}", 5,
                                    finished_task=True, override_pre_message=True, finished_stage=True)

        # tmp solution, should be deal in the future
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.tmp_noexec()

    # ---------- data collection ----------
    def start_collect_data(self):
        self.dls.start_collect_data()
        self.target_server.start_collect_data()
        self.benign_server.start_collect_data()
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.start_collect_data()
        for non_vulnerable_client in self.non_vulnerable_clients:
            non_vulnerable_client.start_collect_data()

    def stop_collect_data(self):
        self.dls.stop_collect_data()
        self.target_server.stop_collect_data()
        self.benign_server.stop_collect_data()
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.stop_collect_data()
        for non_vulnerable_client in self.non_vulnerable_clients:
            non_vulnerable_client.stop_collect_data()

    def centralize_data(self, contain_continuum_log=False):
        """
        using to centralize data from the data logger client to the data logger server
        :param contain_continuum_log: whether the attack scenario should collect log of apache continuum server or not
        """
        for vulnerable_client in self.vulnerable_clients:
            self.dls.centralize_data(vulnerable_client)
        for non_vulnerable_client in self.non_vulnerable_clients:
            self.dls.centralize_data(non_vulnerable_client)
        self.dls.centralize_data(self.target_server, contain_continuum_log)
        self.dls.centralize_data(self.benign_server, contain_continuum_log)

    def centralize_time_files(self, remote_machine, time_files):
        """
        using to centralize time files from the data logger client to the data logger server
        :param remote_machine: which machine you want to get from
        :param time_files: name of time files you want to get from the remote machine
        """
        self.dls.centralize_time_files(remote_machine, time_files)
        # should implement for other scenario *******************************************************

    # ---------- benign behavior reproduction ----------
    def start_reproduce_benign_behavior(self):
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.start_benign_behaviors()
        for non_vulnerable_client in self.non_vulnerable_clients:
            non_vulnerable_client.start_benign_behaviors()

    def stop_reproduce_benign_behavior(self):
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.stop_benign_behaviors()
        for non_vulnerable_client in self.non_vulnerable_clients:
            non_vulnerable_client.stop_benign_behaviors()

    # ---------- attacks ----------
    def attack_mirai(self):
        ProgressHelper.update_scenario("Mirai")
        stage = 2
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is running CNC server and login to manage \
                                    bots", 5, new_stage=True)
        self.attacker_server.mirai_start_cnc_and_login()

        ProgressHelper.update_stage(stage, f"{self.malicious_client.hostname} is running MIRAI and scanning new target \
                                    bots", 5)
        self.malicious_client.mirai_start_malicious()

        self.attacker_server.mirai_wait_for_finished_scan()
        ProgressHelper.update_stage(stage, f"{self.malicious_client.hostname} found bots:", 5, finished_task=True)
        for vulnerable_client in self.vulnerable_clients:
            ProgressHelper.update_stage(stage, f"hostname:{vulnerable_client.hostname}, ip:{vulnerable_client.ip}, \
                                        username:{vulnerable_client.username}, password:{vulnerable_client.password}",
                                        6, finished_task=True)

        self.malicious_client.mirai_stop_malicious()
        ProgressHelper.update_stage(stage, f"Found account information of {self.attacker_server.num_of_new_bots} \
                                    new target bots", 5, finished_task=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is transfering MIRAI to new bots", 5,
                                    new_stage=True)
        self.attacker_server.mirai_transfer_and_start_malicious()

        self.attacker_server.mirai_wait_for_finished_transfer()
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} FINISHED transfering MIRAI to new bots", 5,
                                    finished_task=True, override_pre_message=True)
        ProgressHelper.update_stage(stage, f"{self.attacker_server.num_of_new_bots} new bots were established", 5,
                                    finished_task=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"Bots is starting to DDoS {self.target_server.hostname}", 5,
                                    new_stage=True)
        self.attacker_server.mirai_wait_for_finished_ddos()
        ProgressHelper.update_stage(stage, f"Bots FINISHED to DDoS {self.target_server.hostname}", 5,
                                    finished_task=True, override_pre_message=True)
        ProgressHelper.update_stage(stage, f"Bots FINISHED DDoS {self.target_server.hostname} using: \
                                    DDoS Type: {self.attacker_server.DDoS_type}, Duration: \
                                    {self.attacker_server.DDoS_duration} seconds", 5,
                                    finished_task=True, finished_stage=True)

    def attack_disk_wipe(self):
        ProgressHelper.update_scenario("Disk_Wipe")
        self.attacker_server.disk_wipe_start_metasploit()

        stage = 2
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is exploiting rails_secret_deserialization",
                                    5, new_stage=True)
        self.attacker_server.disk_wipe_first_stage()
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished exploiting rails_secret_deserialization",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing service_persistence",
                                    5, new_stage=True)
        self.attacker_server.disk_wipe_second_stage()
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing service_persistence",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing disk_wipe",
                                    5, new_stage=True)
        self.attacker_server.disk_wipe_third_stage()
        # wait and record timestamp
        timestamp_folder = os.path.join("CREME_backend_execution", "logs", "disk_wipe", "times")
        timestamp_file = "time_stage_3_end.txt"
        OtherHelper.wait_finishing(sleep_time=90, record_time=True, folder=timestamp_folder,
                                   timestamp_file=timestamp_file)
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing disk_wipe",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

    def attack_ransomware(self):
        ProgressHelper.update_scenario("Ransomware")
        self.attacker_server.ransomware_start_metasploit()

        stage = 2
        ProgressHelper.update_stage(stage,
                                    f"{self.attacker_server.hostname} is exploiting ?????",
                                    5, new_stage=True)
        self.attacker_server.ransomware_first_stage()
        ProgressHelper.update_stage(stage,
                                    f"{self.attacker_server.hostname} finished exploiting ?????",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing ?????",
                                    5, new_stage=True)
        self.attacker_server.ransomware_second_stage()
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing ?????",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing ?????",
                                    5, new_stage=True)
        self.attacker_server.ransomware_third_stage()
        # wait and record timestamp
        timestamp_folder = os.path.join("CREME_backend_execution", "logs", "ransomware", "times")
        timestamp_file = "time_stage_3_end.txt"
        OtherHelper.wait_finishing(sleep_time=90, record_time=True, folder=timestamp_folder,
                                   timestamp_file=timestamp_file)
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing ?????",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

    def attack_resource_hijacking(self):
        ProgressHelper.update_scenario("Resource_Hijacking")
        self.attacker_server.resource_hijacking_start_metasploit()

        stage = 2
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is exploiting ?????",
                                    5, new_stage=True)
        self.attacker_server.resource_hijacking_first_stage()
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished exploiting ?????",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing ?????",
                                    5, new_stage=True)
        self.attacker_server.resource_hijacking_second_stage()
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing ?????",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing ?????",
                                    5, new_stage=True)
        self.attacker_server.resource_hijacking_third_stage()
        # wait and record timestamp
        timestamp_folder = os.path.join("CREME_backend_execution", "logs", "resource_hijacking", "times")
        timestamp_file = "time_stage_3_end.txt"
        OtherHelper.wait_finishing(sleep_time=90, record_time=True, folder=timestamp_folder,
                                   timestamp_file=timestamp_file)
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing ?????",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

    def attack_end_point_dos(self):
        ProgressHelper.update_scenario("End_Point_Dos")
        self.attacker_server.end_point_dos_start_metasploit()

        stage = 2
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is exploiting ?????",
                                    5, new_stage=True)
        self.attacker_server.end_point_dos_first_stage()
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished exploiting ?????",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing ?????",
                                    5, new_stage=True)
        self.attacker_server.end_point_dos_second_stage()
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing ?????",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing ?????",
                                    5, new_stage=True)
        self.attacker_server.end_point_dos_third_stage()
        # wait and record timestamp
        timestamp_folder = os.path.join("CREME_backend_execution", "logs", "end_point_dos", "times")
        timestamp_file = "time_stage_3_end.txt"
        OtherHelper.wait_finishing(sleep_time=90, record_time=True, folder=timestamp_folder,
                                   timestamp_file=timestamp_file)
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing ?????",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

    def attack_data_theft(self):
        ProgressHelper.update_scenario("Data_Theft")
        self.attacker_server.data_theft_start_metasploit()

        stage = 2
        ProgressHelper.update_stage(stage,
                                    f"{self.attacker_server.hostname} is exploiting unreal_ircd_3281_backdoor",
                                    5, new_stage=True)
        self.attacker_server.data_theft_first_stage()
        ProgressHelper.update_stage(stage,
                                    f"{self.attacker_server.hostname} finished exploiting unreal_ircd_3281_backdoor",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing docker_daemon_privilege_escalation",
                                    5, new_stage=True)
        self.attacker_server.data_theft_second_stage()
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing docker_daemon_privilege_escalation",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing data_theft",
                                    5, new_stage=True)
        self.attacker_server.data_theft_third_stage()
        # wait and record timestamp
        timestamp_folder = os.path.join("CREME_backend_execution", "logs", "data_theft", "times")
        timestamp_file = "time_stage_3_end.txt"
        OtherHelper.wait_finishing(sleep_time=90, record_time=True, folder=timestamp_folder,
                                   timestamp_file=timestamp_file)
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing data_theft",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

    def attack_rootkit_ransomware(self):
        ProgressHelper.update_scenario("Rootkit_Ransomware")
        self.attacker_server.rootkit_ransomware_start_metasploit()

        stage = 2
        ProgressHelper.update_stage(stage,
                                    f"{self.attacker_server.hostname} is exploiting rails_secret_deserialization",
                                    5, new_stage=True)
        self.attacker_server.rootkit_ransomware_first_stage()
        ProgressHelper.update_stage(stage,
                                    f"{self.attacker_server.hostname} finished exploiting rails_secret_deserialization",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing service_persistence",
                                    5, new_stage=True)
        self.attacker_server.rootkit_ransomware_second_stage()
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing service_persistence",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing rootkit_ransomware",
                                    5, new_stage=True)
        self.attacker_server.rootkit_ransomware_third_stage()
        # wait and record timestamp
        timestamp_folder = os.path.join("CREME_backend_execution", "logs", "rootkit_ransomware", "times")
        timestamp_file = "time_stage_3_end.txt"
        OtherHelper.wait_finishing(sleep_time=90, record_time=True, folder=timestamp_folder,
                                   timestamp_file=timestamp_file)
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing rootkit_ransomware",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

    # ---------- download data to controller ----------
    def download_data_to_controller(self, scenario_log_folder, contain_continuum_log=False, time_filenames=[]):
        """
        using to download data from the data logger server to controller, and save it to scenario_log_folder.
        :param scenario_log_folder: a folder of specific scenario insides the logs folder.
        :param contain_continuum_log: whether the attack scenario should collect log of apache continuum server or not
        :param time_filenames: name of timestamp files
        """
        log_folder = self.dls.controller_path
        tmp_folder_names = ["CREME", "CREME_backend_execution", "logs", scenario_log_folder]
        for folder in tmp_folder_names:
            log_folder = os.path.join(log_folder, folder)

        # ----- download pcap file -----
        traffic = "traffic"
        traffic_folder = os.path.join(log_folder, traffic)

        file_names = [self.dls.tcp_file]
        DownloadDataHelper.get_data(self.dls.ip, self.dls.username, self.dls.password, remote_folder=self.dls.path,
                                    file_names=file_names, local_folder=traffic_folder)

        # ----- download accounting files -----
        accounting = "accounting"
        accounting_folder = os.path.join(log_folder, accounting)

        file_names = []
        file_names.append(self.benign_server.atop_file)
        file_names.append(self.target_server.atop_file)
        for vulnerable_client in self.vulnerable_clients:
            file_names.append(vulnerable_client.atop_file)
        for non_vulnerable_client in self.non_vulnerable_clients:
            file_names.append(non_vulnerable_client.atop_file)

        DownloadDataHelper.get_data(self.dls.ip, self.dls.username, self.dls.password, remote_folder=self.dls.path,
                                    file_names=file_names, local_folder=accounting_folder)

        # ----- download syslog files -----
        syslog = "syslog"
        syslog_folder = os.path.join(log_folder, syslog)
        remote_folder = "/var/log/dataset_generation"
        file_names = ["dataset_generation.log"]

        DownloadDataHelper.get_data(self.dls.ip, self.dls.username, self.dls.password, remote_folder=remote_folder,
                                    file_names=file_names, local_folder=syslog_folder)

        if contain_continuum_log:  # download apache continuum's log
            syslog = "syslog"
            syslog_folder = os.path.join(log_folder, syslog)
            file_names = []
            file_names.append('{0}_continuum.log'.format(self.benign_server.hostname))
            file_names.append('{0}_continuum.log'.format(self.target_server.hostname))

            DownloadDataHelper.get_data(self.dls.ip, self.dls.username, self.dls.password, remote_folder=self.dls.path,
                                        file_names=file_names, local_folder=syslog_folder)

        # ----- download timestamp files -----
        times = "times"
        times_folder = os.path.join(log_folder, times)

        file_names = time_filenames
        DownloadDataHelper.get_data(self.dls.ip, self.dls.username, self.dls.password, remote_folder=self.dls.path,
                                    file_names=file_names, local_folder=times_folder)

    # ---------- run scenario ----------
    def run_mirai(self):
        scenario = "mirai"
        ProgressHelper.update_scenario(scenario)
        self.start_reproduce_benign_behavior()
        self.start_collect_data()
        self.attack_mirai()
        self.stop_collect_data()
        self.stop_reproduce_benign_behavior()
        self.attacker_server.clean_mirai()

        self.centralize_data()
        file_names = ["time_4_start_DDoS.txt"]
        self.centralize_time_files(remote_machine=self.attacker_server, time_files=file_names)
        self.download_data_to_controller(scenario, time_filenames=file_names)

    def run_disk_wipe(self):
        scenario = "disk_wipe"
        ProgressHelper.update_scenario(scenario)
        self.start_reproduce_benign_behavior()
        self.start_collect_data()
        self.attack_disk_wipe()
        self.stop_collect_data()
        self.stop_reproduce_benign_behavior()
        self.attacker_server.clean_disk_wipe()

        self.centralize_data()
        file_names = ["time_stage_1_start.txt", "time_stage_1_end.txt", "time_stage_2_start.txt",
                      "time_stage_2_end.txt", "time_stage_3_start.txt"]
        self.centralize_time_files(remote_machine=self.attacker_server, time_files=file_names)
        self.download_data_to_controller(scenario, time_filenames=file_names)

    def run_ransomware(self):
        scenario = "ransomware"
        ProgressHelper.update_scenario(scenario)
        self.start_reproduce_benign_behavior()
        self.start_collect_data()
        self.attack_ransomware()
        self.stop_collect_data()
        self.stop_reproduce_benign_behavior()
        self.attacker_server.clean_disk_wipe()

        self.centralize_data()
        file_names = ["time_stage_1_start.txt", "time_stage_1_end.txt", "time_stage_2_start.txt",
                      "time_stage_2_end.txt", "time_stage_3_start.txt"]
        self.centralize_time_files(remote_machine=self.attacker_server, time_files=file_names)
        self.download_data_to_controller(scenario, time_filenames=file_names)

    def run_resource_hijacking(self):
        scenario = "resource_hijacking"
        ProgressHelper.update_scenario(scenario)
        self.start_reproduce_benign_behavior()
        self.start_collect_data()
        self.attack_resource_hijacking()
        self.stop_collect_data()
        self.stop_reproduce_benign_behavior()
        self.attacker_server.clean_resource_hijacking()

        self.centralize_data()
        file_names = ["time_stage_1_start.txt", "time_stage_1_end.txt", "time_stage_2_start.txt",
                      "time_stage_2_end.txt", "time_stage_3_start.txt"]
        self.centralize_time_files(remote_machine=self.attacker_server, time_files=file_names)
        self.download_data_to_controller(scenario, time_filenames=file_names)

    def run_end_point_dos(self):
        scenario = "end_point_dos"
        ProgressHelper.update_scenario(scenario)
        self.start_reproduce_benign_behavior()
        self.start_collect_data()
        self.attack_end_point_dos()
        self.stop_collect_data()
        self.stop_reproduce_benign_behavior()
        self.attacker_server.clean_end_point_dos()

        self.centralize_data()
        file_names = ["time_stage_1_start.txt", "time_stage_1_end.txt", "time_stage_2_start.txt",
                      "time_stage_2_end.txt", "time_stage_3_start.txt"]
        self.centralize_time_files(remote_machine=self.attacker_server, time_files=file_names)
        self.download_data_to_controller(scenario, time_filenames=file_names)

    def run_data_theft(self):
        scenario = "data_theft"
        ProgressHelper.update_scenario(scenario)
        self.start_reproduce_benign_behavior()
        self.start_collect_data()
        self.attack_data_theft()
        self.stop_collect_data()
        self.stop_reproduce_benign_behavior()
        self.attacker_server.clean_data_theft()

        # change later
        self.centralize_data()
        file_names = ["time_stage_1_start.txt", "time_stage_1_end.txt", "time_stage_2_start.txt",
                      "time_stage_2_end.txt", "time_stage_3_start.txt"]
        self.centralize_time_files(remote_machine=self.attacker_server, time_files=file_names)
        self.download_data_to_controller(scenario, time_filenames=file_names)

    def run_rootkit_ransomware(self):
        scenario = "rootkit_ransomware"
        ProgressHelper.update_scenario(scenario)
        self.start_reproduce_benign_behavior()
        self.start_collect_data()
        self.attack_rootkit_ransomware()
        self.stop_collect_data()
        self.stop_reproduce_benign_behavior()
        self.attacker_server.clean_rootkit_ransomware()

        # change later
        self.centralize_data()
        file_names = ["time_stage_1_start.txt", "time_stage_1_end.txt", "time_stage_2_start.txt",
                      "time_stage_2_end.txt", "time_stage_3_start.txt"]
        self.centralize_time_files(remote_machine=self.attacker_server, time_files=file_names)
        self.download_data_to_controller(scenario, time_filenames=file_names)

    # ---------- process data ----------
    def process_data_mirai(self, log_folder):
        """
        this function use to create labeling_file that contain information to label accounting and traffic data for
        Mirai attack scenario, also return abnormal_hostnames, normal_hostnames, timestamps_syslog to process and
        label syslog
        """
        folder_times = os.path.join(log_folder, "times")
        t1, t2, t3, t4 = ProcessDataHelper.get_time_stamps_mirai(folder_times, self.attacker_server.DDoS_duration)
        # t = [t1, t2, t2, t3, t3, t4, t4, t5]
        t = [t1, t2, t2, t3, t3, t4]

        labels = [1, 1, 1]  # only for syslog
        tactic_names = ['Initial Access', 'Command and Control', 'Impact']
        technique_names = ['Valid Accounts', 'Non-Application Layer Protocol', 'Network Denial of Service']
        sub_technique_names = ['SubTechnique-Stage-1', 'SubTechnique-Stage-2', 'SubTechnique-Stage-3']

        src_ips_1 = []
        des_ips_1 = []
        normal_ips_1 = []
        abnormal_hostnames_1 = []
        normal_hostnames_1 = []

        src_ips_1.append(self.malicious_client.ip)
        for vulnerable_client in self.vulnerable_clients:
            des_ips_1.append(vulnerable_client.ip)
            abnormal_hostnames_1.append(vulnerable_client.hostname)
        for non_vulnerable_client in self.non_vulnerable_clients:
            normal_ips_1.append(non_vulnerable_client.ip)
            normal_hostnames_1.append(non_vulnerable_client.hostname)
        normal_ips_1.append(self.target_server.ip)
        normal_hostnames_1.append(self.target_server.hostname)
        normal_ips_1.append(self.benign_server.ip)
        normal_hostnames_1.append(self.benign_server.hostname)

        src_ips_2 = []
        des_ips_2 = []
        normal_ips_2 = []
        abnormal_hostnames_2 = []
        normal_hostnames_2 = []

        src_ips_2.append(self.attacker_server.ip)
        for vulnerable_client in self.vulnerable_clients:
            des_ips_2.append(vulnerable_client.ip)
            abnormal_hostnames_2.append(vulnerable_client.hostname)
        for non_vulnerable_client in self.non_vulnerable_clients:
            normal_ips_2.append(non_vulnerable_client.ip)
            normal_hostnames_2.append(non_vulnerable_client.hostname)
        normal_ips_2.append(self.target_server.ip)
        normal_hostnames_2.append(self.target_server.hostname)
        normal_ips_2.append(self.benign_server.ip)
        normal_hostnames_2.append(self.benign_server.hostname)

        src_ips_3 = []
        des_ips_3 = []
        normal_ips_3 = []
        abnormal_hostnames_3 = []
        normal_hostnames_3 = []

        for vulnerable_client in self.vulnerable_clients:
            src_ips_3.append(vulnerable_client.ip)
            abnormal_hostnames_3.append(vulnerable_client.hostname)
        des_ips_3.append(self.target_server.ip)
        abnormal_hostnames_3.append(self.target_server.hostname)
        for non_vulnerable_client in self.non_vulnerable_clients:
            normal_ips_3.append(non_vulnerable_client.ip)
            normal_hostnames_3.append(non_vulnerable_client.hostname)
        normal_ips_3.append(self.benign_server.ip)
        normal_hostnames_3.append(self.benign_server.hostname)

        src_ips = [src_ips_1, src_ips_2, src_ips_3]
        des_ips = [des_ips_1, des_ips_2, des_ips_3]
        normal_ips = [normal_ips_1, normal_ips_2, normal_ips_3]
        normal_hostnames = [normal_hostnames_1, normal_hostnames_2, normal_hostnames_3]
        abnormal_hostnames = [abnormal_hostnames_1, abnormal_hostnames_2, abnormal_hostnames_3]
        drop_cmd_list = ['kworker']

        labeling_file_path = os.path.join(log_folder, "labeling_file_path.txt")

        ProcessDataHelper.make_labeling_file(labeling_file_path, tactic_names, technique_names,
                                             sub_technique_names, t, src_ips, des_ips, normal_ips, normal_hostnames,
                                             abnormal_hostnames, drop_cmd_list)

        timestamps_syslog = [[t1, t2], [t2, t3], [t3, t4]]

        return labeling_file_path, timestamps_syslog, abnormal_hostnames, normal_hostnames, labels, tactic_names,\
            technique_names, sub_technique_names

    def process_data_general_scenario(self, log_folder, labels, tactic_names, technique_names, sub_technique_names):
        """
        this function use to create labeling_file that contain information to label accounting and traffic data for
        general attack scenarios (excepting Mirai), also return abnormal_hostnames, normal_hostnames, timestamps_syslog to process and
        label syslog
        """
        folder_times = os.path.join(log_folder, "times")
        t1, t2, t3, t4, t5, t6 = ProcessDataHelper.get_time_stamps(folder_times)
        t = [t1, t2, t3, t4, t5, t6]

        src_ips_1 = []
        des_ips_1 = []
        normal_ips_1 = []
        abnormal_hostnames_1 = []
        normal_hostnames_1 = []

        src_ips_1.append(self.attacker_server.ip)
        des_ips_1.append(self.target_server.ip)
        abnormal_hostnames_1.append(self.target_server.hostname)
        normal_ips_1.append(self.benign_server.ip)
        normal_hostnames_1.append(self.benign_server.hostname)
        normal_ips_1.append(self.malicious_client.ip)
        for vulnerable_client in self.vulnerable_clients:
            normal_ips_1.append(vulnerable_client.ip)
            normal_hostnames_1.append(vulnerable_client.hostname)
        for non_vulnerable_client in self.non_vulnerable_clients:
            normal_ips_1.append(non_vulnerable_client.ip)
            normal_hostnames_1.append(non_vulnerable_client.hostname)

        src_ips_2 = src_ips_1[:]
        des_ips_2 = des_ips_1[:]
        normal_ips_2 = normal_ips_1[:]
        abnormal_hostnames_2 = abnormal_hostnames_1[:]
        normal_hostnames_2 = normal_hostnames_1[:]

        src_ips_3 = src_ips_1[:]
        des_ips_3 = des_ips_1[:]
        normal_ips_3 = normal_ips_1[:]
        abnormal_hostnames_3 = abnormal_hostnames_1[:]
        normal_hostnames_3 = normal_hostnames_1[:]

        src_ips = [src_ips_1, src_ips_2, src_ips_3]
        des_ips = [des_ips_1, des_ips_2, des_ips_3]
        normal_ips = [normal_ips_1, normal_ips_2, normal_ips_3]
        normal_hostnames = [normal_hostnames_1, normal_hostnames_2, normal_hostnames_3]
        abnormal_hostnames = [abnormal_hostnames_1, abnormal_hostnames_2, abnormal_hostnames_3]
        drop_cmd_list = ['kworker']

        labeling_file_path = os.path.join(log_folder, "labeling_file_path.txt")

        ProcessDataHelper.make_labeling_file(labeling_file_path, tactic_names, technique_names,
                                             sub_technique_names, t, src_ips, des_ips, normal_ips, normal_hostnames,
                                             abnormal_hostnames, drop_cmd_list)

        timestamps_syslog = [[t1, t2], [t3, t4], [t5, t6]]

        return labeling_file_path, timestamps_syslog, abnormal_hostnames, normal_hostnames, labels, tactic_names, \
            technique_names, sub_technique_names

    def process_data_disk_wipe(self, log_folder):
        """
        this function use to create labeling_file that contain information to label accounting and traffic data for
        Disk_Wipe attack scenario, also return abnormal_hostnames, normal_hostnames, timestamps_syslog to process and
        label syslog
        """
        labels = [1, 1, 1]  # only for syslog
        tactic_names = ['Initial Access', 'Command and Control', 'Impact']
        technique_names = ['Valid Accounts', 'Non-Application Layer Protocol', 'Network Denial of Service']
        sub_technique_names = ['SubTechnique-Stage-1', 'SubTechnique-Stage-2', 'SubTechnique-Stage-3']

        return self.process_data_general_scenario(log_folder, labels, tactic_names, technique_names, sub_technique_names)

    def process_data_data_theft(self, log_folder):
        """
        this function use to create labeling_file that contain information to label accounting and traffic data for
        Data_Theft attack scenario, also return abnormal_hostnames, normal_hostnames, timestamps_syslog to process and
        label syslog
        """
        labels = [1, 1, 1]  # only for syslog
        tactic_names = ['Initial Access', 'Command and Control', 'Impact']
        technique_names = ['Valid Accounts', 'Non-Application Layer Protocol', 'Network Denial of Service']
        sub_technique_names = ['SubTechnique-Stage-1', 'SubTechnique-Stage-2', 'SubTechnique-Stage-3']

        return self.process_data_general_scenario(log_folder, labels, tactic_names, technique_names,
                                                  sub_technique_names)

    def process_data_rootkit_ransomware(self, log_folder):
        """
        this function use to create labeling_file that contain information to label accounting and traffic data for
        Rootkit_Ransomware attack scenario, also return abnormal_hostnames, normal_hostnames, timestamps_syslog to process and
        label syslog
        """
        labels = [1, 1, 1]  # only for syslog
        tactic_names = ['Initial Access', 'Command and Control', 'Impact']
        technique_names = ['Valid Accounts', 'Non-Application Layer Protocol', 'Network Denial of Service']
        sub_technique_names = ['SubTechnique-Stage-1', 'SubTechnique-Stage-2', 'SubTechnique-Stage-3']

        return self.process_data_general_scenario(log_folder, labels, tactic_names, technique_names,
                                                  sub_technique_names)

    def process_data(self):
        stage = 5
        ProgressHelper.update_stage(stage, f"Start processing data ...", 5, new_stage=True)

        big_list = []
        traffic_files = []
        atop_files = []
        log_folder = "CREME_backend_execution/logs"

        # syslog
        input_files = []
        scenarios_timestamps = []
        scenarios_abnormal_hostnames = []
        scenarios_normal_hostnames = []
        scenarios_labels = []
        scenarios_tactics = []
        scenarios_techniques = []
        scenarios_sub_techniques = []

        if Creme.mirai:
            ProgressHelper.update_stage(stage, f"Processing the data of Mirai scenario", 5)

            scenario = "mirai"
            log_folder_mirai = os.path.join(log_folder, scenario)
            labeling_file_path, timestamps_syslog, abnormal_hostnames, normal_hostnames, labels, tactics,\
                techniques, sub_techniques = self.process_data_mirai(log_folder_mirai)
            accounting_folder = "accounting"
            traffic_file = os.path.join("traffic", self.dls.tcp_file)
            information = [labeling_file_path, log_folder_mirai, accounting_folder, traffic_file]

            big_list.append(information)
            traffic_files.append("label_traffic_mirai.csv")
            atop_files.append("label_atop_mirai.csv")

            # syslog
            syslog_file = os.path.join(log_folder_mirai, "syslog")
            syslog_file = os.path.join(syslog_file, "dataset_generation.log")
            input_files.append(syslog_file)
            scenarios_timestamps.append(timestamps_syslog)
            scenarios_abnormal_hostnames.append(abnormal_hostnames)
            scenarios_normal_hostnames.append(normal_hostnames)

            scenarios_labels.append(labels)
            scenarios_tactics.append(tactics)
            scenarios_techniques.append(techniques)
            scenarios_sub_techniques.append(sub_techniques)

            ProgressHelper.update_stage(stage, f"Finished processing the data of Mirai scenario", 5,
                                        finished_task=True, override_pre_message=True)

        if Creme.disk_wipe:
            ProgressHelper.update_stage(stage, f"Processing the data of Disk_Wipe scenario", 5)

            scenario = "disk_wipe"
            log_folder_disk_wipe = os.path.join(log_folder, scenario)
            labeling_file_path, timestamps_syslog, abnormal_hostnames, normal_hostnames, labels, tactics,\
                techniques, sub_techniques = self.process_data_disk_wipe(log_folder_disk_wipe)
            accounting_folder = "accounting"
            traffic_file = os.path.join("traffic", self.dls.tcp_file)
            information = [labeling_file_path, log_folder_disk_wipe, accounting_folder, traffic_file]

            big_list.append(information)
            traffic_files.append("label_traffic_disk_wipe.csv")
            atop_files.append("label_atop_disk_wipe.csv")

            # syslog
            syslog_file = os.path.join(log_folder_disk_wipe, "syslog")
            syslog_file = os.path.join(syslog_file, "dataset_generation.log")
            input_files.append(syslog_file)
            scenarios_timestamps.append(timestamps_syslog)
            scenarios_abnormal_hostnames.append(abnormal_hostnames)
            scenarios_normal_hostnames.append(normal_hostnames)

            scenarios_labels.append(labels)
            scenarios_tactics.append(tactics)
            scenarios_techniques.append(techniques)
            scenarios_sub_techniques.append(sub_techniques)

            ProgressHelper.update_stage(stage, f"Finished processing the data of Disk_Wipe scenario", 5,
                                        finished_task=True, override_pre_message=True)

        if Creme.data_theft:
            ProgressHelper.update_stage(stage, f"Processing the data of Data_Theft scenario", 5)

            scenario = "data_theft"
            log_folder_data_theft = os.path.join(log_folder, scenario)
            labeling_file_path, timestamps_syslog, abnormal_hostnames, normal_hostnames, labels, tactics,\
                techniques, sub_techniques = self.process_data_data_theft(log_folder_data_theft)
            accounting_folder = "accounting"
            traffic_file = os.path.join("traffic", self.dls.tcp_file)
            information = [labeling_file_path, log_folder_data_theft, accounting_folder, traffic_file]

            big_list.append(information)
            traffic_files.append("label_traffic_data_theft.csv")
            atop_files.append("label_atop_data_theft.csv")

            # syslog
            syslog_file = os.path.join(log_folder_data_theft, "syslog")
            syslog_file = os.path.join(syslog_file, "dataset_generation.log")
            input_files.append(syslog_file)
            scenarios_timestamps.append(timestamps_syslog)
            scenarios_abnormal_hostnames.append(abnormal_hostnames)
            scenarios_normal_hostnames.append(normal_hostnames)

            scenarios_labels.append(labels)
            scenarios_tactics.append(tactics)
            scenarios_techniques.append(techniques)
            scenarios_sub_techniques.append(sub_techniques)

            ProgressHelper.update_stage(stage, f"Finished processing the data of data_theft scenario", 5,
                                        finished_task=True, override_pre_message=True)

        if Creme.rootkit_ransomware:
            ProgressHelper.update_stage(stage, f"Processing the data of Rootkit_Ransomware scenario", 5)

            scenario = "rootkit_ransomware"
            log_folder_rootkit_ransomware = os.path.join(log_folder, scenario)
            labeling_file_path, timestamps_syslog, abnormal_hostnames, normal_hostnames, labels, tactics,\
                techniques, sub_techniques = self.process_data_rootkit_ransomware(log_folder_rootkit_ransomware)
            accounting_folder = "accounting"
            traffic_file = os.path.join("traffic", self.dls.tcp_file)
            information = [labeling_file_path, log_folder_rootkit_ransomware, accounting_folder, traffic_file]

            big_list.append(information)
            traffic_files.append("label_traffic_rootkit_ransomware.csv")
            atop_files.append("label_atop_rootkit_ransomware.csv")

            # syslog
            syslog_file = os.path.join(log_folder_rootkit_ransomware, "syslog")
            syslog_file = os.path.join(syslog_file, "dataset_generation.log")
            input_files.append(syslog_file)
            scenarios_timestamps.append(timestamps_syslog)
            scenarios_abnormal_hostnames.append(abnormal_hostnames)
            scenarios_normal_hostnames.append(normal_hostnames)

            scenarios_labels.append(labels)
            scenarios_tactics.append(tactics)
            scenarios_techniques.append(techniques)
            scenarios_sub_techniques.append(sub_techniques)

            ProgressHelper.update_stage(stage, f"Finished processing the data of rootkit_ransomware scenario", 5,
                                        finished_task=True, override_pre_message=True)

        ProgressHelper.update_stage(stage, f"Processing the accounting and network packet data sources", 5)
        folder_traffic = os.path.join(log_folder, "label_traffic")
        final_name_traffic = "label_traffic.csv"
        folder_atop = os.path.join(log_folder, "label_accounting")
        final_name_atop = "label_accounting.csv"
        time_window_traffic = self.dls.time_window_traffic  # second
        ProcessDataHelper.handle_accounting_packet_all_scenario(big_list, folder_traffic, traffic_files,
                                                                final_name_traffic, folder_atop, atop_files,
                                                                final_name_atop, time_window_traffic)
        # balance data and filter features
        ProcessDataHelper.balance_data(folder_atop, final_name_atop)
        ProcessDataHelper.filter_features(folder_atop, final_name_atop, 0.1)
        ProcessDataHelper.filter_features(folder_traffic, final_name_traffic, 0.04)
        ProgressHelper.update_stage(stage, f"Finished processing the accounting and network packet data sources", 5,
                                    finished_task=True, override_pre_message=True)

        ProgressHelper.update_stage(stage, f"Processing the syslog data source", 5)
        dls_hostname = self.dls.hostname
        result_path_syslog = os.path.join(log_folder, "label_syslog")
        final_name_syslog = "label_syslog.csv"
        ProcessDataHelper.handle_syslog(input_files, scenarios_timestamps, scenarios_abnormal_hostnames,
                                        scenarios_normal_hostnames, scenarios_labels, scenarios_tactics,
                                        scenarios_techniques, scenarios_sub_techniques, dls_hostname,
                                        result_path_syslog, final_name_syslog)
        # filter features
        ProcessDataHelper.filter_features(result_path_syslog, final_name_syslog, 0.1)
        ProgressHelper.update_stage(stage, f"Finished processing the syslog data source", 5,
                                    finished_task=True, override_pre_message=True, finished_stage=True)

        data_sources = []
        data_sources.append({"name": "accounting", "folder": folder_atop, "file": final_name_atop})
        data_sources.append({"name": "traffic", "folder": folder_traffic, "file": final_name_traffic})
        data_sources.append({"name": "syslog", "folder": result_path_syslog, "file": final_name_syslog})

        return data_sources

    # ---------- train ML ----------
    def train_ML_accuracy(self, stage, data_sources):
        output_folder = os.path.join("CREME_backend_execution", "evaluation_results")
        output_folder = os.path.join(output_folder, "accuracy")
        # models_name should update to let users select at the website *************
        models_name = Creme.models_name
        for data_source in data_sources:
            name = data_source["name"]
            folder = data_source["folder"]
            file = data_source["file"]
            ProgressHelper.update_stage(stage, "Training {0}".format(name), 6)
            output_folder, output_file = TrainMLHelper.accuracy(name, folder, file, output_folder, models_name)
            ProgressHelper.update_stage(stage, "Finished training {0}".format(name), 6,
                                        finished_task=True, override_pre_message=True)

    def train_ML_efficiency(self, stage, data_sources):
        result = dict()
        for data_source in data_sources:
            name = data_source["name"]
            folder = data_source["folder"]
            file = data_source["file"]
            ProgressHelper.update_stage(stage, "Training {0}".format(name), 6)
            rfecv = TrainMLHelper.efficiency(folder, file)
            result[name] = rfecv
            ProgressHelper.update_stage(stage, "Finished training {0}".format(name), 6,
                                        finished_task=True, override_pre_message=True)

        return result

    def train_ML(self, data_sources):
        stage = 6
        ProgressHelper.update_stage(stage, f"Start training models for Accuracy:", 5, new_stage=True)
        # accuracy
        self.train_ML_accuracy(stage, data_sources)

        ProgressHelper.update_stage(stage, f"Start training models for Efficiency:", 5)
        # efficiency
        eff_result = self.train_ML_efficiency(stage, data_sources)

        ProgressHelper.update_stage(stage, f"Finished training models:", 5, finished_task=True, finished_stage=True)

        return eff_result

    # ---------- evaluation ----------
    def efficiency_evaluation(self, stage, eff_result):
        eff_folder = os.path.join("CREME_backend_execution", "evaluation_results")
        eff_folder = os.path.join(eff_folder, "efficiency")
        eff_file = "efficiency.csv"
        eff_folder, eff_file = EvaluationHelper.generate_existing_efficiency(eff_folder, eff_file)
        if eff_folder is not None and eff_file is not None:
            for data_source, rfecv in eff_result.items():
                ProgressHelper.update_stage(stage, "{0}".format(data_source), 6)
                EvaluationHelper.efficiency(data_source, rfecv, eff_folder, eff_file)
                ProgressHelper.update_stage(stage, "Finished {0}".format(data_source), 6,
                                            finished_task=True, override_pre_message=True)

    def coverage_evaluation(self, cov_result):
        cov_folder = os.path.join("CREME_backend_execution", "evaluation_results")
        cov_folder = os.path.join(cov_folder, "coverage")
        cov_file = "coverage.csv"
        weights = Creme.weights
        cov_folder, cov_file = EvaluationHelper.generate_existing_coverage(cov_folder, cov_file, weights)

        # calculate CREME's coverage *******************************
        pass

    def evaluation(self, eff_result):
        stage = 7
        ProgressHelper.update_stage(stage, f"Start Efficiency evaluation:", 5, new_stage=True)
        # efficiency
        self.efficiency_evaluation(stage, eff_result)

        ProgressHelper.update_stage(stage, f"Start Coverage evaluation:", 5)
        # coverage
        cov_result = None
        self.coverage_evaluation(cov_result)
        ProgressHelper.update_stage(stage, f"Finished evaluation:", 5, finished_task=True, finished_stage=True)

    def run(self):
        self.configure()

        if Creme.mirai:
            self.run_mirai()
        if Creme.disk_wipe:
            self.run_disk_wipe()
        # if Creme.ransomware:
        #     self.run_ransomware()
        # if Creme.resource_hijacking:
        #     self.run_resource_hijacking()
        # if Creme.end_point_dos:
        #     self.run_end_point_dos()
        if Creme.data_theft:
            self.run_data_theft()
        if Creme.rootkit_ransomware:
            self.run_rootkit_ransomware()

        # process data
        data_sources = self.process_data()

        # train ML
        eff_result = self.train_ML(data_sources)

        # evaluation
        self.evaluation(eff_result)

