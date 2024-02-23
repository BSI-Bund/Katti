from envelope import Envelope
from katti.CeleryApps.KattiApp import katti_app
from pydantic import BaseModel
from pydantic import EmailStr
from katti.KattiUtils.Configs.ConfigKeys import DEFAULT_MAIL_FOM, MAIL_HOST


class Mail(BaseModel):
    receivers: list[EmailStr]
    subject: str
    body: str
    cc: list[EmailStr] = []
    from_: str | None = None
    #bcc: list[EmailStr] = Field(default_factory=list)


@katti_app.task(bind=True)
def send_mail(self, mail: Mail):
    envelope_mail = Envelope(mail.body).subject(mail.subject)
    for receiver in mail.receivers:
        envelope_mail = envelope_mail.to(receiver)
    for cc in mail.cc:
        envelope_mail = envelope_mail.cc(cc)
    #for bcc in mail.bcc:
    #    envelope_mail = envelope_mail.bcc(bcc)
    mai_from = mail.from_ if mail.from_ else DEFAULT_MAIL_FOM
    envelope_mail.smtp(MAIL_HOST).from_(mail.from_).send()
    envelope_mail.smtp_quit()
