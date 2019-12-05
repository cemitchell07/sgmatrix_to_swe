import json
import ssl

class Config:
    def __init__(self):
        self.config = json.loads(open("config.json").read())
    
    def get_host_name(self):
        return self.config["PXGRID_HOST"]

    def get_node_name(self):
        return self.config["PXGRID_NAME"]

    def get_password(self):
        if self.config["PASSWORD"] is not None:
            return self.config["PASSWORD"]
        else:
            return ''

    def get_description(self):
        return self.config["PXGRID_DESC"]

    def get_ssl_context(self):
        context = ssl.create_default_context()
        if self.config["PXGRID_CLIENTCERT"] is not None:
            context.load_cert_chain(certfile=self.config["PXGRID_CLIENTCERT"],
                                    keyfile=self.config["PXGRID_CLIENTKEY"],
                                    password=self.config["PXGRID_KEYPASS"])
        context.load_verify_locations(cafile=self.config["PXGRID_CACERT"])
        return context

    def get_swe_host(self):
        return self.config["SMC_HOST"]

    def get_swe_user(self):
        return self.config["SMC_USER"]

    def get_swe_pass(self):
        return self.config["SMC_PASSWORD"]

    def get_swe_tenant(self):
        return self.config["SMC_TENANT_ID"]
