from .helper import DownloadDataHelper, ProgressHelper, ProcessDataHelper, TrainMLHelper, EvaluationHelper, OtherHelper
import os
from multiprocessing import Process
from threading import Thread
class CremeMinimal:
    mirai = True
    ransomware = True
    resource_hijacking = True
    disk_wipe = True
    end_point_dos = True

    data_theft = True
    rootkit_ransomware = True

    models_name = ["decision_tree", "naive_bayes", "extra_tree", "knn", "random_forest", "XGBoost"]

    skip_configuration = False
    skip_reproduction = False
    skip_data_processing = False
    skip_ML_training = False
    skip_evaluation = False

    # TODO: should update to allow users define weights on the website
    weights = {"attack_types": 4 / 10 / 20, "attack_scenarios": 2 / 10 / 20, "data_sources": 1 / 10 / 6,
               "labeled_data": 1 / 10 / 6, "feature_set": 1 / 10 / 6, "metadata": 1 / 10}

    def __init__(self, dls, target_server, benign_server, vulnerable_clients, non_vulnerable_clients,
                 attacker_server, malicious_client, mirai, ransomware, resource_hijacking, disk_wipe, end_point_dos,
                 data_theft, rootkit_ransomware, skip_configuration, skip_reproduction, skip_data_processing, skip_ML_training, skip_evaluation):
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
        CremeMinimal.mirai = mirai
        CremeMinimal.ransomware = ransomware
        CremeMinimal.resource_hijacking = resource_hijacking
        CremeMinimal.disk_wipe = disk_wipe
        CremeMinimal.end_point_dos = end_point_dos
        CremeMinimal.data_theft = data_theft
        CremeMinimal.rootkit_ransomware = rootkit_ransomware

        # Skip 
        CremeMinimal.skip_configuration = skip_configuration
        CremeMinimal.skip_reproduction = skip_reproduction
        CremeMinimal.skip_data_processing = skip_data_processing
        CremeMinimal.skip_ML_training = skip_ML_training
        CremeMinimal.skip_evaluation = skip_evaluation

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
        self.dls.configure()
        self.target_server.configure()
        self.benign_server.configure()
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.configure()
        for non_vulnerable_client in self.non_vulnerable_clients:
            non_vulnerable_client.configure()
        self.attacker_server.configure()
        self.malicious_client.configure()
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

    def centralize_data(self, other_data=False, remote_paths=[], remote_files=[]):
        """
        using to centralize data from the data logger client to the data logger server
        :param other_data: except atop files, whether we needs to collect other data at the data logger client or not
        :param remote_paths: paths correspond to files
        :param remote_files: files correspond to paths
        """
        for vulnerable_client in self.vulnerable_clients:
            self.dls.centralize_data(vulnerable_client)
        for non_vulnerable_client in self.non_vulnerable_clients:
            self.dls.centralize_data(non_vulnerable_client)
        self.dls.centralize_data(self.target_server, other_data, remote_paths, remote_files)
        self.dls.centralize_data(self.benign_server, other_data, remote_paths, remote_files)

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
        self.attacker_server.mirai_start_cnc_and_login()
        self.malicious_client.mirai_start_malicious()
        self.attacker_server.mirai_wait_for_finished_scan()
        self.malicious_client.mirai_stop_malicious()
        self.attacker_server.mirai_transfer_and_start_malicious()
        self.attacker_server.mirai_wait_for_finished_transfer()
        self.attacker_server.mirai_wait_for_finished_ddos()
    def attack_disk_wipe(self):
        # print("Starting metasploit! " + "\033[92m")
        # self.attacker_server.disk_wipe_start_metasploit()
        # self.attacker_server.disk_wipe_first_stage()
        # self.attacker_server.disk_wipe_second_stage()
        # self.attacker_server.disk_wipe_third_stage()
        print("Starting Attack! " + "\033[92m")
        self.attacker_server.disk_wipe_full_stages()
        # wait and record timestamp
        timestamp_folder = os.path.join("CREME_backend_execution", "logs", "disk_wipe", "times")
        timestamp_file = "time_stage_3_end.txt"
        OtherHelper.wait_finishing(sleep_time=90, record_time=True, folder=timestamp_folder,
                                   timestamp_file=timestamp_file)
    def attack_ransomware(self):
        self.attacker_server.ransomware_start_metasploit()
        self.attacker_server.ransomware_first_stage()
        self.attacker_server.ransomware_second_stage()
        self.attacker_server.ransomware_third_stage()
        # wait and record timestamp
        timestamp_folder = os.path.join("CREME_backend_execution", "logs", "ransomware", "times")
        timestamp_file = "time_stage_3_end.txt"
        OtherHelper.wait_finishing(sleep_time=90, record_time=True, folder=timestamp_folder,
                                   timestamp_file=timestamp_file)
    def attack_resource_hijacking(self):
        self.attacker_server.resource_hijacking_start_metasploit()
        self.attacker_server.resource_hijacking_first_stage()
        self.attacker_server.resource_hijacking_second_stage()
        self.attacker_server.resource_hijacking_third_stage()
        # wait and record timestamp
        timestamp_folder = os.path.join("CREME_backend_execution", "logs", "resource_hijacking", "times")
        timestamp_file = "time_stage_3_end.txt"
        OtherHelper.wait_finishing(sleep_time=90, record_time=True, folder=timestamp_folder,
                                   timestamp_file=timestamp_file)
    def attack_end_point_dos(self):
        self.attacker_server.end_point_dos_start_metasploit()
        self.attacker_server.end_point_dos_first_stage()
        self.attacker_server.end_point_dos_second_stage()
        self.attacker_server.end_point_dos_third_stage()
        # wait and record timestamp
        timestamp_folder = os.path.join("CREME_backend_execution", "logs", "end_point_dos", "times")
        timestamp_file = "time_stage_3_end.txt"
        OtherHelper.wait_finishing(sleep_time=90, record_time=True, folder=timestamp_folder,
                                   timestamp_file=timestamp_file)
    def attack_data_theft(self):
        self.attacker_server.data_theft_start_metasploit()
        self.attacker_server.data_theft_first_stage()
        self.attacker_server.data_theft_second_stage()
        self.attacker_server.data_theft_third_stage()
        # wait and record timestamp
        timestamp_folder = os.path.join("CREME_backend_execution", "logs", "data_theft", "times")
        timestamp_file = "time_stage_3_end.txt"
        OtherHelper.wait_finishing(sleep_time=90, record_time=True, folder=timestamp_folder,
                                   timestamp_file=timestamp_file)
    def attack_rootkit_ransomware(self):
        self.attacker_server.rootkit_ransomware_start_metasploit()
        self.attacker_server.rootkit_ransomware_first_stage()
        self.attacker_server.rootkit_ransomware_second_stage()
        self.attacker_server.rootkit_ransomware_third_stage()
        # wait and record timestamp
        timestamp_folder = os.path.join("CREME_backend_execution", "logs", "rootkit_ransomware", "times")
        timestamp_file = "time_stage_3_end.txt"
        OtherHelper.wait_finishing(sleep_time=90, record_time=True, folder=timestamp_folder,
                                   timestamp_file=timestamp_file)
    # ---------- download data to controller ----------
    def download_data_to_controller(self, scenario_log_folder, time_filenames=[], other_files_flag=False,
                                    local_folders=[], remote_files=[]):
        """
        using to download data from the data logger server to controller, and save it to scenario_log_folder.
        :param scenario_log_folder: a folder of specific scenario insides the logs folder.
        :param time_filenames: name of timestamp files
        :param other_files_flag: whether we needs to collect other data to controller or not
        :param local_folders: local folders at controller
        :param remote_files: other files at remote_machine (not pcap, accounting, syslog, timestamp)
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

        if other_files_flag:  # download other logs/files
            for i, tmp_folder in enumerate(local_folders):
                # syslog = "syslog"
                local_folder = os.path.join(log_folder, tmp_folder)
                file_names = []
                file_names.append(remote_files[i])
                # file_names.append('{0}_continuum.log'.format(self.benign_server.hostname))
                # file_names.append('{0}_continuum.log'.format(self.target_server.hostname))

                DownloadDataHelper.get_data(self.dls.ip, self.dls.username, self.dls.password, remote_folder=self.dls.path,
                                            file_names=file_names, local_folder=local_folder)

        # ----- download timestamp files -----
        times = "times"
        times_folder = os.path.join(log_folder, times)

        file_names = time_filenames
        DownloadDataHelper.get_data(self.dls.ip, self.dls.username, self.dls.password, remote_folder=self.dls.path,
                                    file_names=file_names, local_folder=times_folder)

    # ---------- cleaning ----------
    def clean_data_collection(self):
        # TODO: think about whether we really need this one ?
        #  Or restarting rsyslog when entering the attack scenarios is enough?

        self.target_server.clean_data_collection()
        self.benign_server.clean_data_collection()
        self.dls.clean_data_collection()

    # ---------- cleaning ----------
    def restart_rsyslog_service(self):
        self.target_server.restart_rsyslog()
        self.benign_server.restart_rsyslog()
        self.dls.restart_rsyslog()

    # ---------- run scenario ----------
    def run_mirai(self):
        scenario = "mirai"
        # restart the rsyslog at data logger server
        self.restart_rsyslog_service()

        self.start_reproduce_benign_behavior()
        self.start_collect_data()
        self.attack_mirai()
        self.stop_collect_data()
        self.stop_reproduce_benign_behavior()
        self.clean_data_collection()
        self.attacker_server.clean_mirai()

        self.centralize_data()
        file_names = ["time_4_start_DDoS.txt"]
        self.centralize_time_files(remote_machine=self.attacker_server, time_files=file_names)
        self.download_data_to_controller(scenario, time_filenames=file_names)

    def run_disk_wipe(self):
        scenario = "disk_wipe"
        # restart the rsyslog at data logger server
        self.restart_rsyslog_service()

        self.start_reproduce_benign_behavior()
        self.start_collect_data()
        self.attack_disk_wipe()
        self.stop_collect_data()
        self.stop_reproduce_benign_behavior()
        self.clean_data_collection()
        self.attacker_server.clean_disk_wipe()
        self.target_server.clean_disk_wipe()

        self.centralize_data()
        file_names = ["time_stage_1_start.txt", "time_stage_1_end.txt", "time_stage_2_start.txt",
                      "time_stage_2_end.txt", "time_stage_3_start.txt"]
        self.centralize_time_files(remote_machine=self.attacker_server, time_files=file_names)
        self.download_data_to_controller(scenario, time_filenames=file_names)

    def run_ransomware(self):
        scenario = "ransomware"
        # restart the rsyslog at data logger server
        self.restart_rsyslog_service()

        self.start_reproduce_benign_behavior()
        self.start_collect_data()
        self.attack_ransomware()
        self.stop_collect_data()
        self.stop_reproduce_benign_behavior()
        self.clean_data_collection()
        self.attacker_server.clean_ransomware()
        self.target_server.clean_ransomware()

        self.centralize_data()
        file_names = ["time_stage_1_start.txt", "time_stage_1_end.txt", "time_stage_2_start.txt",
                      "time_stage_2_end.txt", "time_stage_3_start.txt"]
        self.centralize_time_files(remote_machine=self.attacker_server, time_files=file_names)
        self.download_data_to_controller(scenario, time_filenames=file_names)

    def run_resource_hijacking(self):
        scenario = "resource_hijacking"
        # restart the rsyslog at data logger server
        self.restart_rsyslog_service()

        # restart continuum services at target server and benign server
        self.target_server.restart_continuum()
        self.benign_server.restart_continuum()

        self.start_reproduce_benign_behavior()
        self.start_collect_data()
        self.attack_resource_hijacking()
        self.stop_collect_data()
        self.stop_reproduce_benign_behavior()
        self.clean_data_collection()
        self.attacker_server.clean_resource_hijacking()
        self.target_server.clean_resource_hijacking()

        remote_paths = ["/opt/apache_continuum/apache-continuum-1.4.2/logs"]
        remote_files = ["continuum.log"]
        self.centralize_data(True, remote_paths, remote_files)

        file_names = ["time_stage_1_start.txt", "time_stage_1_end.txt", "time_stage_2_start.txt",
                      "time_stage_2_end.txt", "time_stage_3_start.txt"]
        self.centralize_time_files(remote_machine=self.attacker_server, time_files=file_names)

        local_folders = ["syslog", "syslog"]
        remote_files = []
        remote_files.append("{0}_continuum.log".format(self.benign_server.hostname))
        remote_files.append("{0}_continuum.log".format(self.target_server.hostname))
        self.download_data_to_controller(scenario, time_filenames=file_names, other_files_flag=True,
                                         local_folders=local_folders, remote_files=remote_files)

    def run_end_point_dos(self):
        scenario = "end_point_dos"
        # restart the rsyslog at data logger server
        self.restart_rsyslog_service()

        # config ulimit to limit the number of processes for normal users,
        # opening many processes will cause to problems about stuck atop collection
        # TODO: currently, ulimit can't be applied to ssh session.
        #self.target_server.configure_end_point_dos_ulimit()

        self.start_reproduce_benign_behavior()
        self.start_collect_data()
        self.attack_end_point_dos()
        self.stop_collect_data()
        self.stop_reproduce_benign_behavior()
        self.clean_data_collection()
        self.attacker_server.clean_end_point_dos()
        self.target_server.clean_end_point_dos()

        self.centralize_data()
        file_names = ["time_stage_1_start.txt", "time_stage_1_end.txt", "time_stage_2_start.txt",
                      "time_stage_2_end.txt"]
        self.centralize_time_files(remote_machine=self.attacker_server, time_files=file_names)
        self.download_data_to_controller(scenario, time_filenames=file_names)

    def run_data_theft(self):
        scenario = "data_theft"
        # restart the rsyslog at data logger server
        self.restart_rsyslog_service()

        self.start_reproduce_benign_behavior()
        self.start_collect_data()
        self.attack_data_theft()
        self.stop_collect_data()
        self.stop_reproduce_benign_behavior()
        self.clean_data_collection()
        self.attacker_server.clean_data_theft()
        self.target_server.clean_data_theft()

        # change later
        self.centralize_data()
        file_names = ["time_stage_1_start.txt", "time_stage_1_end.txt", "time_stage_2_start.txt",
                      "time_stage_2_end.txt", "time_stage_3_start.txt"]
        self.centralize_time_files(remote_machine=self.attacker_server, time_files=file_names)
        self.download_data_to_controller(scenario, time_filenames=file_names)

    def run_rootkit_ransomware(self):
        scenario = "rootkit_ransomware"
        # restart the rsyslog at data logger server
        self.restart_rsyslog_service()

        self.start_reproduce_benign_behavior()
        self.start_collect_data()
        self.attack_rootkit_ransomware()
        self.stop_collect_data()
        self.stop_reproduce_benign_behavior()
        self.clean_data_collection()
        self.attacker_server.clean_rootkit_ransomware()
        self.target_server.clean_rootkit_ransomware()

        # change later
        self.centralize_data()
        file_names = ["time_stage_1_start.txt", "time_stage_1_end.txt", "time_stage_2_start.txt",
                      "time_stage_2_end.txt", "time_stage_3_start.txt"]
        self.centralize_time_files(remote_machine=self.attacker_server, time_files=file_names)
        self.download_data_to_controller(scenario, time_filenames=file_names)

    # ---------- process data ----------
    def process_data_mirai(self, log_folder):
        """
        This function use to create labeling_file that contain information to label accounting and traffic data for
        Mirai attack scenario, also return abnormal_hostnames, normal_hostnames, timestamps_syslog to process and
        label syslog.
        If technique and sub_technique are the same, it means that the technique doesn't have sub-techniques
        """
        folder_times = os.path.join(log_folder, "times")
        t1, t2, t3, t4 = ProcessDataHelper.get_time_stamps_mirai(folder_times, self.attacker_server.DDoS_duration)
        # t = [t1, t2, t2, t3, t3, t4, t4, t5]
        t = [t1, t2, t2, t3, t3, t4]

        labels = [1, 1, 1]  # only for syslog
        tactic_names = ['Initial Access', 'Command and Control', 'Impact']
        technique_names = ['Valid Accounts', 'Non-Application Layer Protocol', 'Network Denial of Service']
        sub_technique_names = ['Local Accounts', 'Non-Application Layer Protocol', 'Direct Network Flood']
        
        """Other possible labels
        Tactic -> technique -> sub technique
        Initial Access -> Valid Accounts -> Default Accounts
        Lateral Movement -> Remote Services -> SSH
        Resource Development -> Acquire Infrastructure -> Botnet
        """
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
        pattern_normal_cmd_list = [['kworker'], ['kworker'], ['kworker']]

        labeling_file_path = os.path.join(log_folder, "labeling_file_path.txt")

        ProcessDataHelper.make_labeling_file(labeling_file_path, tactic_names, technique_names,
                                             sub_technique_names, t, src_ips, des_ips, normal_ips, normal_hostnames,
                                             abnormal_hostnames, pattern_normal_cmd_list)

        timestamps_syslog = [[t1, t2], [t2, t3], [t3, t4]]

        return labeling_file_path, timestamps_syslog, abnormal_hostnames, normal_hostnames, labels, tactic_names,\
            technique_names, sub_technique_names

    def process_data_general_scenario(self, log_folder, labels, tactic_names, technique_names, sub_technique_names,
                                      force_abnormal_cmd_list=[[],[],[]]):
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
        pattern_normal_cmd_list = [['kworker'], ['kworker'], ['kworker']]

        labeling_file_path = os.path.join(log_folder, "labeling_file_path.txt")

        # TODO: labels are not used, think about using it to label accounting and traffic data (pass to
        #  make_labeling_file which is used to create a file as parameters for labeling accounting and traffic).
        #  Currently, hard-code label 1 for abnormal data in filter_label_atop.py and make_label_subflow.py
        ProcessDataHelper.make_labeling_file(labeling_file_path, tactic_names, technique_names,
                                             sub_technique_names, t, src_ips, des_ips, normal_ips, normal_hostnames,
                                             abnormal_hostnames, pattern_normal_cmd_list, force_abnormal_cmd_list)

        timestamps_syslog = [[t1, t2], [t3, t4], [t5, t6]]

        return labeling_file_path, timestamps_syslog, abnormal_hostnames, normal_hostnames, labels, tactic_names, \
            technique_names, sub_technique_names

    def process_data_disk_wipe(self, log_folder):
        """
        this function use to create labeling_file that contain information to label accounting and traffic data for
        Disk_Wipe attack scenario, also return abnormal_hostnames, normal_hostnames, timestamps_syslog to process and
        label syslog.
        If technique and sub_technique are the same, it means that the technique doesn't have sub-techniques.
        """
        labels = [1, 1, 1]  # only for syslog
        tactic_names = ['Initial Access', 'Command and Control', 'Impact']
        technique_names = ['Exploit Public-Facing Application', 'Non-Application Layer Protocol', 'Disk wipe']
        sub_technique_names = ['Exploit Public-Facing Application', 'Non-Application Layer Protocol', 'Disk Content Wipe']
        """Other possible labels
        Initial Access -> Exploit Public-Facing Application
        Persistence
        Impact -> Data Destruction or Disk Wipe -> Disk Content Wipe or Disk Structure Wipe

        """
        return self.process_data_general_scenario(log_folder, labels, tactic_names, technique_names, sub_technique_names)

    def process_data_data_theft(self, log_folder):
        """
        this function use to create labeling_file that contain information to label accounting and traffic data for
        Data_Theft attack scenario, also return abnormal_hostnames, normal_hostnames, timestamps_syslog to process and
        label syslog.
        If technique and sub_technique are the same, it means that the technique doesn't have sub-techniques.
        """
        labels = [1, 1, 1]  # only for syslog
        tactic_names = ['Initial Access', 'Command and Control', 'Exfiltration']
        technique_names = ['Exploit Public-Facing Application', 'Non-Application Layer Protocol', 'Exfiltration Over C2 Channel']
        sub_technique_names = ['Exploit Public-Facing Application', 'Non-Application Layer Protocol', 'Exfiltration Over C2 Channel']

        return self.process_data_general_scenario(log_folder, labels, tactic_names, technique_names,
                                                  sub_technique_names)

    def process_data_rootkit_ransomware(self, log_folder):
        """
        this function use to create labeling_file that contain information to label accounting and traffic data for
        Rootkit_Ransomware attack scenario, also return abnormal_hostnames, normal_hostnames, timestamps_syslog to process and
        label syslog.
        If technique and sub_technique are the same, it means that the technique doesn't have sub-techniques.
        """
        labels = [1, 1, 1]  # only for syslog
        tactic_names = ['Initial Access', 'Command and Control', 'Impact']
        technique_names = ['Exploit Public-Facing Application', 'Non-Application Layer Protocol', 'Data Encrypted']
        sub_technique_names = ['Exploit Public-Facing Application', 'Non-Application Layer Protocol', 'Data Encrypted']

        return self.process_data_general_scenario(log_folder, labels, tactic_names, technique_names,
                                                  sub_technique_names)

    def process_data_ransomware(self, log_folder):
        """
        this function use to create labeling_file that contain information to label accounting and traffic data for
        Ransomware attack scenario, also return abnormal_hostnames, normal_hostnames, timestamps_syslog to process and
        label syslog.
        If technique and sub_technique are the same, it means that the technique doesn't have sub-techniques.
        """
        labels = [1, 1, 1]  # only for syslog
        tactic_names = ['Initial Access', 'Command and Control', 'Impact']
        technique_names = ['Exploit Public-Facing Application', 'Non-Application Layer Protocol', 'Data Encrypted']
        sub_technique_names = ['Exploit Public-Facing Application', 'Non-Application Layer Protocol', 'Data Encrypted']
        """Other possible labels
        Initial Access -> Exploit Public-Facing Application
        Persistence
        """
        return self.process_data_general_scenario(log_folder, labels, tactic_names, technique_names,
                                                  sub_technique_names)

    def process_data_resource_hijacking(self, log_folder):
        """
        this function use to create labeling_file that contain information to label accounting and traffic data for
        Resource_Hijacking attack scenario, also return abnormal_hostnames, normal_hostnames, timestamps_syslog to process and
        label syslog.
        If technique and sub_technique are the same, it means that the technique doesn't have sub-techniques.
        """
        labels = [1, 1, 1]  # only for syslog
        tactic_names = ['Initial Access', 'Command and Control', 'Impact']
        technique_names = ['Exploit Public-Facing Application', 'Non-Application Layer Protocol', 'Resource Hijacking']
        sub_technique_names = ['Exploit Public-Facing Application', 'Non-Application Layer Protocol', 'Resource Hijacking']

        return self.process_data_general_scenario(log_folder, labels, tactic_names, technique_names,
                                                  sub_technique_names)

    def process_data_end_point_dos(self, log_folder):
        """
        this function use to create labeling_file that contain information to label accounting and traffic data for
        End_Point_Dos attack scenario, also return abnormal_hostnames, normal_hostnames, timestamps_syslog to process and
        label syslog.
        If technique and sub_technique are the same, it means that the technique doesn't have sub-techniques.
        """
        labels = [1, 1, 1]  # only for syslog
        tactic_names = ['Initial Access', 'Persistence', 'Impact']
        technique_names = ['Exploit Public-Facing Application', 'Create Account', 'Endpoint DoS']
        sub_technique_names = ['Exploit Public-Facing Application', 'Local Account', 'OS Exhaustion Flood']

        # TODO: currently, using only cmd to label accounting data. There is a problem if normal and abnormal processes
        #  have the same cmd. Think about how to solve this problem???
        force_abnormal_cmd_list = [[],[],["<bash>"]]  # pattern of force bomb process

        return self.process_data_general_scenario(log_folder, labels, tactic_names, technique_names,
                                                  sub_technique_names, force_abnormal_cmd_list)

    def process_data(self):
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

        if CremeMinimal.mirai:
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

        if CremeMinimal.disk_wipe:
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

        if CremeMinimal.data_theft:
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

        if CremeMinimal.rootkit_ransomware:
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

        if CremeMinimal.ransomware:
            scenario = "ransomware"
            log_folder_ransomware = os.path.join(log_folder, scenario)
            labeling_file_path, timestamps_syslog, abnormal_hostnames, normal_hostnames, labels, tactics,\
                techniques, sub_techniques = self.process_data_ransomware(log_folder_ransomware)
            accounting_folder = "accounting"
            traffic_file = os.path.join("traffic", self.dls.tcp_file)
            information = [labeling_file_path, log_folder_ransomware, accounting_folder, traffic_file]

            big_list.append(information)
            traffic_files.append("label_traffic_ransomware.csv")
            atop_files.append("label_atop_ransomware.csv")

            # syslog
            syslog_file = os.path.join(log_folder_ransomware, "syslog")
            syslog_file = os.path.join(syslog_file, "dataset_generation.log")
            input_files.append(syslog_file)
            scenarios_timestamps.append(timestamps_syslog)
            scenarios_abnormal_hostnames.append(abnormal_hostnames)
            scenarios_normal_hostnames.append(normal_hostnames)

            scenarios_labels.append(labels)
            scenarios_tactics.append(tactics)
            scenarios_techniques.append(techniques)
            scenarios_sub_techniques.append(sub_techniques)

        if CremeMinimal.resource_hijacking:
            scenario = "resource_hijacking"
            log_folder_resource_hijacking = os.path.join(log_folder, scenario)
            labeling_file_path, timestamps_syslog, abnormal_hostnames, normal_hostnames, labels, tactics,\
                techniques, sub_techniques = self.process_data_resource_hijacking(log_folder_resource_hijacking)
            accounting_folder = "accounting"
            traffic_file = os.path.join("traffic", self.dls.tcp_file)
            information = [labeling_file_path, log_folder_resource_hijacking, accounting_folder, traffic_file]

            big_list.append(information)
            traffic_files.append("label_traffic_resource_hijacking.csv")
            atop_files.append("label_atop_resource_hijacking.csv")

            # syslog
            syslog_folder = os.path.join(log_folder_resource_hijacking, "syslog")
            syslog_file = os.path.join(syslog_folder, "dataset_generation.log")
            input_files.append(syslog_file)
            scenarios_timestamps.append(timestamps_syslog)
            scenarios_abnormal_hostnames.append(abnormal_hostnames)
            scenarios_normal_hostnames.append(normal_hostnames)
            # merge continuum logs to dataset_generation.log
            continuum_log_files = []
            tmp_hostnames = []
            continuum_log_files.append(os.path.join(syslog_folder, "{0}_continuum.log".format(self.benign_server.hostname)))
            tmp_hostnames.append(self.benign_server.hostname)
            continuum_log_files.append(os.path.join(syslog_folder, "{0}_continuum.log".format(self.target_server.hostname)))
            tmp_hostnames.append(self.target_server.hostname)
            scenarios_labels.append(labels)
            scenarios_tactics.append(tactics)
            scenarios_techniques.append(techniques)
            scenarios_sub_techniques.append(sub_techniques)

        if CremeMinimal.end_point_dos:
            scenario = "end_point_dos"
            log_folder_end_point_dos = os.path.join(log_folder, scenario)
            labeling_file_path, timestamps_syslog, abnormal_hostnames, normal_hostnames, labels, tactics,\
                techniques, sub_techniques = self.process_data_end_point_dos(log_folder_end_point_dos)
            accounting_folder = "accounting"
            traffic_file = os.path.join("traffic", self.dls.tcp_file)
            information = [labeling_file_path, log_folder_end_point_dos, accounting_folder, traffic_file]

            big_list.append(information)
            traffic_files.append("label_traffic_end_point_dos.csv")
            atop_files.append("label_atop_end_point_dos.csv")

            # syslog
            syslog_file = os.path.join(log_folder_end_point_dos, "syslog")
            syslog_file = os.path.join(syslog_file, "dataset_generation.log")
            input_files.append(syslog_file)
            scenarios_timestamps.append(timestamps_syslog)
            scenarios_abnormal_hostnames.append(abnormal_hostnames)
            scenarios_normal_hostnames.append(normal_hostnames)

            scenarios_labels.append(labels)
            scenarios_tactics.append(tactics)
            scenarios_techniques.append(techniques)
            scenarios_sub_techniques.append(sub_techniques)

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
        ProcessDataHelper.balance_data(folder_traffic, final_name_traffic, balanced_label_zero = False)
        ProcessDataHelper.filter_features(folder_atop, final_name_atop, 0.1)
        ProcessDataHelper.filter_features(folder_traffic, final_name_traffic, 0.04)
        dls_hostname = self.dls.hostname
        result_path_syslog = os.path.join(log_folder, "label_syslog")
        final_name_syslog = "label_syslog.csv"
        ProcessDataHelper.handle_syslog(input_files, scenarios_timestamps, scenarios_abnormal_hostnames,
                                        scenarios_normal_hostnames, scenarios_labels, scenarios_tactics,
                                        scenarios_techniques, scenarios_sub_techniques, dls_hostname,
                                        result_path_syslog, final_name_syslog)
        # filter features
        ProcessDataHelper.filter_features(result_path_syslog, final_name_syslog, 0.1)
        data_sources = []
        data_sources.append({"name": "accounting", "folder": folder_atop, "file": final_name_atop})
        data_sources.append({"name": "traffic", "folder": folder_traffic, "file": final_name_traffic})
        data_sources.append({"name": "syslog", "folder": result_path_syslog, "file": final_name_syslog})

        return data_sources

    def run(self):
        if not CremeMinimal.skip_configuration:
            input("Press enter to continue to configuration")
            self.configure()
        if not CremeMinimal.skip_reproduction:
            if CremeMinimal.mirai:
                self.run_mirai()
            if CremeMinimal.disk_wipe:
                input("Press enter to continue to diskwipe")
                self.run_disk_wipe()
            if CremeMinimal.ransomware:
                self.run_ransomware()
            if CremeMinimal.resource_hijacking:
                self.run_resource_hijacking()
            if CremeMinimal.end_point_dos:
                self.run_end_point_dos()
            if CremeMinimal.data_theft:
                self.run_data_theft()
            if CremeMinimal.rootkit_ransomware:
                self.run_rootkit_ransomware()
        # process data
        if not CremeMinimal.skip_data_processing:
            data_sources = self.process_data()

